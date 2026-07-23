# Threat Observable v2 Protocol Draft

Status: normative design draft for GH-82. No wire implementation, proof
relation, production key, or deployment is approved by this document.

## 1. Purpose

ThreatHint v1 is a bounded, canonical claim about an opaque 32-byte
`threat_hash`. The client supplies that value; the protocol does not currently
derive it from a file or an observable. The v1 Groth16 statement binds the hash
and the remaining v1 metadata to its domain and network, but it does not prove
how the hash was produced.

Actionable analysis needs concrete, deliberately disclosed observables without
turning paths, host context, credentials, private infrastructure, or arbitrary
file contents into public threat intelligence. This draft defines the minimum
v2 boundary that a later schema and validator must implement.

## 2. Security Claims

The protocol may claim only the property actually checked:

| Check | Permitted claim | Not proved |
|---|---|---|
| SHA-256 of the domain concatenated with the canonical bundle equals `observable_commitment` | The revealed canonical bundle is consistent with the commitment | Truth, maliciousness, authorship, or artifact derivation |
| v2 statement binds `artifact_hash` and `observable_commitment` | The proof statement cannot be changed without invalidating that proof | That either value was honestly produced |
| A future reviewed derivation circuit constrains both values | Only the exact relation documented by that circuit | Reporter identity, authorization, or anonymity unless separately proved |
| Multiple independent reports agree | Bounded corroboration under the membership and Sybil assumptions | Ground truth |

A hash is a commitment and correlation identifier, not encryption. A
content-addressed CID is not access control. A public YARA rule can reveal every
literal or byte pattern it contains.

## 3. Preferred v2 Statement

The preferred ThreatHint v2 statement has separate public fields for:

- `artifact_hash`: SHA-256 of the locally scanned artifact;
- `observable_commitment`: commitment to the canonical bundle below;
- `confidence_bps`, `disclosure_class`, `report_nonce`, and `observed_at`;
- trusted `network_id` and a new v2 statement domain.

Both hashes must be statement-bound by a new reviewed relation. Existing
ThreatHint v1 bytes, schema version, statement prefix, public-input encoding,
relation manifest, and verifier remain unchanged.

An interim profile that places `observable_commitment` in v1 `threat_hash`
would lose the separate artifact binding. It may be useful in isolated tests,
but it is not production-promotable and must not be described as proving
artifact derivation.

## 4. Canonical Observable Bundle v1

The bundle is strict UTF-8 JSON with this exact field order:

```json
{"schema_version":1,"disclosure_policy":"public_auto_v1","scope":{"platform":"linux","format":"elf"},"observables":[{"kind":"api_import","value":"mmap"}]}
```

The nested `scope` order is `platform`, `format`. Every observable order is
`kind`, `value`. Unknown or duplicate fields, duplicate observables,
non-canonical whitespace, alternative escaping, and trailing bytes are
rejected. Parsers must reserialize and require byte identity.

Bounds and closed values:

| Field | Allowed values |
|---|---|
| Canonical bundle | 1..=4096 bytes |
| `schema_version` | exact integer `1` |
| `disclosure_policy` | `public_auto_v1` or `review_required_v1` |
| `scope.platform` | `windows`, `linux`, `macos`, `any` |
| `scope.format` | `pe`, `elf`, `macho`, `script`, `document`, `unknown` |
| `observables` | 1..=16 unique entries, sorted by `(kind, value)` byte order |
| `observables[].kind` | exact closed set `file_sha256`, `api_import`, `byte_pattern`; reject every other value |
| `file_sha256` value | exactly 64 lowercase hexadecimal characters |
| `api_import` value | 1..=96 printable ASCII characters from the restricted token grammar below |
| `byte_pattern` value | exact token grammar below; 8..=64 byte-position tokens with at least eight fixed-byte tokens |

The `api_import` grammar is:

```text
[A-Za-z_][A-Za-z0-9_.@-]{0,95}
```

`byte_pattern` is parsed as follows:

1. The value is ASCII and has no leading or trailing whitespace.
2. Split only on one literal ASCII space (`0x20`). Empty tokens, tabs,
   newlines, and repeated spaces are invalid.
3. The result contains 8..=64 tokens. Each token represents one byte position.
4. A token is either exact `??` or exactly two lowercase hexadecimal
   characters matching `[0-9a-f]{2}`.
5. At least eight tokens must be fixed hexadecimal bytes rather than `??`.

No normalization is performed for any kind. Validate `kind` and its exact value
grammar first, then reject duplicate exact `(kind, value)` pairs, then require
strict ascending UTF-8 byte order. `byte_pattern` requires
`review_required_v1`. `public_auto_v1` permits only `file_sha256` and
`api_import`. No network observable or unrestricted string literal exists in
this version.

## 5. Commitment

The exact commitment is:

```text
SHA256(
  "prometheus-threat-observable-bundle-v1\0" ||
  u8(len(network_id)) || utf8(network_id) ||
  hex_decode(report_nonce) ||
  u32be(len(canonical_bundle)) || canonical_bundle
)
```

`network_id` follows the existing lowercase alphanumeric-and-hyphen grammar and
is 2..=64 bytes. `report_nonce` is exactly 32 bytes encoded as lowercase hex in
the enclosing hint. This binding makes commitments report- and network-specific
to reduce passive cross-network correlation.

Matching this digest to `observable_commitment` proves only byte consistency.
Artifact derivation requires an independently reviewed circuit that explicitly
constrains the artifact hash and observable extraction.

## 6. Deny-by-default Privacy Policy

The producer validates before commitment and disclosure. The Guardian repeats
all structural validation before analysis. Neither side logs rejected values.

The first implementation must reject:

- paths, usernames, hostnames, device IDs, process command lines, environment
  values, credentials, tokens, keys, cookies, and connection strings;
- private, loopback, link-local, internal, or unregistered network names and
  addresses;
- unrestricted literals, URLs, registry keys, mutex names, document text, and
  source-code fragments;
- control characters, non-ASCII values, hidden normalization, and values above
  the exact bounds;
- automatic public disclosure of `byte_pattern` entries.

`review_required_v1` is local-only in the first implementation. Any IPC, P2P,
Guardian analyzer, committee, IPFS, chain, or public-rule boundary must reject
the complete bundle even if the sender labels it reviewed. A later release may
promote it only through a separately specified authenticated approval envelope
that binds the exact `observable_commitment`, approver authority, purpose,
recipient scope, expiry, and nonce. Self-labeling a bundle is never approval.
Until that protocol exists and passes review, reviewed bundles may be
canonicalized and tested locally but must not leave the producer boundary.

## 7. Processing Boundary

The safe sequence is:

1. Detect locally and compute `artifact_hash`.
2. Extract only closed observable types.
3. Apply the local deny-by-default policy.
4. Canonicalize and compute `observable_commitment`.
5. Produce a v2 proof only with an approved relation and artifacts.
6. Verify the exact hint and bundle independently at the Guardian.
7. Analyze only the validated observable values.
8. Treat generated rule bytes as potentially public before committee, IPFS, or
   chain submission.

No v1 hint may be silently upgraded, paired with an unbound bundle, or routed
to the existing actionable analyzer.

## 8. Promotion Gates

Implementation may begin with a local canonical bundle type and validator, but
network or analyzer promotion requires:

- frozen cross-language test vectors for valid and invalid canonical bundles;
- a separate ThreatHint v2 schema and protocol identifier;
- an exact v2 statement specification and reviewed relation source;
- independently approved relation, proving/verifying keys, and vectors;
- owner-only durable pairing of one verified hint with one validated bundle;
- replay, freshness, size, concurrency, logging, and cancellation tests;
- privacy review of every observable class and generated-rule publication;
- real multi-host evidence and protected CI/Security/Pages success.

Until those gates pass, verified ThreatHint v1 remains hash-only,
zero-confidence, no-rule, and non-submittable.
