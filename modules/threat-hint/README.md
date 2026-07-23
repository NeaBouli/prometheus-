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
analysis. The owner-only verifier ingress exists, but operated acceptance stays
fail-closed as `busy` until independently approved production relation
artifacts and vectors are installed.

No `PeerId`, wallet, address, chain, Guardian identity, membership,
signing key, reporter reward, KAS/PROM, slash, commit-reveal field is part of
this schema.

## Canonical Observable Bundle v1 (local-only)

`ObservableBundle` is a separate local schema utility for canonical observable
bundles. It is not connected to any client, P2P, proof, transport, or analyzer
path. The Rust utility and the isolated Python counterpart consume the same
byte-exact valid/invalid vector corpus.

The utility:

- only accepts local canonical JSON;
- keeps disclosure policy and enum spaces closed and exact;
- rejects non-canonical encodings, duplicate keys, duplicate observables,
  non-UTF-8, and malformed byte order;
- rejects `public_auto_v1` bundles that contain `byte_pattern`.

No arbitrary-string builder is exposed; bundle values enter this API only
through strict canonical parsing. Validation proves structural conformance, not
extractor provenance or semantic privacy. There is no transport or semantic
privacy guarantee for any bundle, including `review_required_v1`. No logger or
payload is emitted on validation failure, fixed errors never include rejected
values, and value-bearing debug/repr output is disabled.

The local Rust producers remain kind-specific and accept no paths or observable
strings. `produce_file_sha256_bundle` hashes exact caller-supplied bytes and
emits one `public_auto_v1` digest. `produce_byte_pattern_bundle` selects a
bounded 8..=64-byte range from exact caller-supplied bytes, replaces positions
chosen by a boolean mask with `??`, requires at least eight fixed bytes, and
always emits `review_required_v1`. Neither profile authorizes transport, and
the byte-pattern result must remain local until a separate authenticated
approval protocol is specified and reviewed.
