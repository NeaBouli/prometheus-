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
the byte-pattern result must remain local.

`produce_elf_api_import_bundle` accepts exact Linux ELF bytes plus one checked
index, derives scope internally, validates and byte-sorts/deduplicates dynamic
imports, and always emits `review_required_v1`. Its exactly pinned read-only
parser rejects artifacts above 16 MiB and dynamic-symbol tables above 4096
entries. It accepts no path, caller-supplied import string, platform, format,
or generic value. The result remains local and does not prove provenance,
maliciousness, privacy approval, or disclosure authorization.

`produce_pe_api_import_bundle` applies the same boundary to exact Windows PE32
or PE32+ bytes. It derives `windows`/`pe` internally, rejects artifacts above
16 MiB, stops after 4096 import entries, rejects ordinal imports and names
outside the closed grammar, rejects a bound IAT when no unbound lookup table is
available, and byte-sorts/deduplicates named imports before a checked index
selects one. Library names are never observable values. Every result is
`review_required_v1`; the API exposes no path, caller-supplied import string,
transport, proof, analyzer, wallet, chain, or promotion operation.

## ThreatHint v2 Statement (local parsing only)

`ThreatHintV2Statement` is separate from the schema-v1 transport envelope. It
parses only exact canonical JSON containing schema version 2, distinct artifact
hash and observable commitment, bounded confidence, a closed structural
disclosure class, report nonce, positive observed time, and a network that must
match separately trusted local context. Its length-prefixed domain-separated
digest binds every canonical field.

The Rust parser and isolated Python counterpart consume one shared exact-byte
valid/invalid corpus. No generic producer, signer, relation, proof acceptance,
pairing, transport, replay authority, analyzer, wallet, or chain integration is
provided. The type proves structural binding only, not artifact derivation,
truth, maliciousness, privacy safety, authorization, or anonymity.

## Observable Approval v1 (local verification only)

`verify_observable_approval` verifies one exact canonical, BIP340-authenticated
approval statement for one exact `review_required_v1` bundle. The caller must
provide independently trusted context: report nonce, x-only approver public
key, recipient-scope digest, network ID, and current time. The current time
must never be attacker-controlled. The verifier recomputes
the bundle commitment, enforces an inclusive validity window of at most one
hour, verifies the signature over a domain-separated canonical body, and
returns an opaque result with a deterministic approval ID.

The Rust verifier and isolated Python counterpart consume one shared
public-only vector. No signing or private-key API exists. Verification performs
no transport, persistence, analyzer promotion, disclosure, publication, proof,
wallet, or chain action. The approval nonce and ID identify repeated
submissions but do not prevent replay; any future consumer must implement
durable one-time use and a separately reviewed authority and recipient policy.
The Python return value is data only: object identity is never authorization,
and a future consumer must invoke verification within its own trusted call
path rather than accept a caller-supplied result object.
