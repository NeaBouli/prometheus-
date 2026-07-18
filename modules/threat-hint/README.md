# Prometheus ThreatHint Schema

`prometheus-threat-hint` defines the OS-independent canonical schema shared by
the Light Client and Guardian transport. It does not connect to the network,
verify Groth16 proofs, authorize reporters, or award PROM.

Schema v1 is canonical JSON with this exact field order:

```text
schema_version, threat_hash, confidence_bps, indicator_type,
proof_system, proof, report_nonce, observed_at
```

The parser rejects unknown or duplicate fields, noncanonical bytes, trailing
data, zero confidence or timestamps, malformed lowercase hex, proofs outside
`1..=1024` bytes, and envelopes above 2048 bytes. Confidence uses integer basis
points and is never transported as a float.

`development_stub_v1` is only a local-development representation. The Light
Client refuses to build it in beta or mainnet modes. `groth16_kip16_v1` bytes
remain opaque here and require a separate audited verifier before Guardian
analysis. The operated Guardian sidecar therefore rejects all ThreatHints until
that dedicated owner-only verifier ingress exists.

No `PeerId`, wallet, address, chain, Guardian identity, membership, signing key,
reporter reward, KAS/PROM, slash, or commit-reveal field is part of the schema.
