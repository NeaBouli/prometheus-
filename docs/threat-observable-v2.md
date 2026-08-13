# Threat Observable v2 Protocol Draft

Status: normative design draft for GH-82. Merged and exact-main-verified GH-86
implements only the isolated local Rust/Python bundle validators and shared
vectors in Sections 4-5. Merged and exact-main-verified GH-90 adds one local Rust producer for a
single `file_sha256` observable from exact caller-supplied bytes, plus shared
vectors independently consumed by Python. Merged and exact-main-verified GH-94 adds one local
Rust producer for a bounded `byte_pattern` derived from exact caller-supplied
bytes, offset, and boolean wildcard mask; it is always
`review_required_v1`, and Python independently validates the shared vectors.
GH-103 adds one local Rust producer for a checked `api_import` selected from
exact caller-supplied Linux ELF bytes. It derives scope internally, bounds
artifact bytes and dynamic symbols, always emits `review_required_v1`, and is
independently checked against shared exact-byte ELF vectors by Python.
Merged and exact-main-verified GH-121 applies the same boundary to Windows PE32 and PE32+
imports. It accepts exact artifact bytes plus a checked index, derives
`windows`/`pe`, caps artifacts at 16 MiB, import descriptors at 4096, and
thunk entries at 4096, rejects
ordinal or grammar-invalid imports, and is independently checked against a
synthetic shared PE32+ vector by Python. PE32 and PE32+ parser dispatch plus
their architecture-specific thunk and ordinal handling are covered in Rust.
Merged and exact-main-verified GH-107 adds an isolated local Rust/Python verifier for one
canonical, short-lived BIP340 approval statement over one exact
`review_required_v1` bundle. It authenticates a statement only and is not
connected to transport, analysis, disclosure, publication, proof, wallet, or
chain paths.
Merged and exact-main-verified GH-114 adds isolated local Rust/Python parsers for the canonical v2 statement
defined in Section 3 plus one shared exact-byte corpus. No proof relation,
production key, pairing, transport, analyzer promotion, or deployment is
approved by this document.

Merged and exact-main-verified GH-117, but not production-deployed, adds strict
canonical Rust/Python parsers for a bounded opaque-proof envelope and a
19-field `RelationManifest-v2`, plus one atomic data-only binding. The binding
requires a separately trusted network and exact raw-manifest SHA-256 before
parsing, recomputes the manifest-domain statement digest, and derives two
claimed 16-byte big-endian public-input halves. It performs no Groth16
verification, source/key loading or approval, ceremony, transport, promotion,
analysis, wallet, chain, or rollout action.

The merged GH-117 pipeline also adds a Python-only, non-consuming
privacy/proof preflight. Its owner-only read-only TOML policy pins one network,
BIP340 approver key, opaque recipient scope, and exact nonzero raw-manifest
SHA-256. The public call accepts no independent statement, network, key, scope,
or manifest anchor: it derives the statement only from the bound envelope,
requires `review_required_v1`, recomputes the bundle commitment against one
trusted report nonce, and verifies the short-lived approval in the same call.
It opens no SQLite database and returns only data hashes and identifiers.
Success is not Groth16 verification, privacy approval, disclosure authority,
replay consumption, transport admission, analyzer promotion, or rollout state.

GH-167 adds only the bounded repository transport substrate. One exact
Rust/Python frame carries the original proof envelope, Observable Bundle,
approval wire, and an untrusted report-nonce lookup key over the independent
`/prometheus/threat-hint/2.0.0` protocol into owner-only local IPC. Rust parses
against an explicitly trusted local network before IPC. Python reparses the
same bytes, resolves the nonce only through trusted active-session state,
obtains time from a trusted local clock, and then calls the existing governed
promotion boundary. This same-host substrate does not approve production
relation/key/ceremony artifacts, semantic or actionable analysis, disclosure,
public multi-host operation, models/YARA, wallet, chain, rewards, or deployment.

Merged and exact-main-verified GH-170 is a separate candidate-rule prerequisite. It replaces the
Guardian's substring-only YARA shape check with exact-pinned, bounded,
compile-only YARA-X validation, while disabling includes and rejecting imports,
multiple rules, compiler errors, and warnings. It does not connect the v2
non-actionable worker to a model or YARA generator, scan any data, establish
semantic quality, or authorize an actionable result, disclosure, submission,
publication, or production operation.

GH-173 is a separate local candidate pending protected merge. It adds one
deterministic governed-worker analyzer that turns already approved local
`api_import` and `byte_pattern` values into a bounded memory-only draft, reuses
the GH-170 compile-only boundary, and atomically records only exact input
bindings, per-kind counts, a nonce-bound candidate-binding SHA-256, and compile
status. File hashes are count-only, the source is never persisted, schema-v1
results remain readable, and the result has no model, confidence,
`should_submit`, scan, disclosure, publication, chain, reward, deployment, or
production authority.

A separate merged local Rust `verify-v2` boundary closes the mechanical proof
verification step. It owner-loads retained canonical manifest bytes plus fixed
`relation-source.bin` and `verifying-key.bin` siblings, binds their exact
manifest sizes and SHA-256 anchors, accepts only canonical compressed BN254
keys/proofs, derives both field inputs only through the v2 binding, and emits
silent process status. Runtime never resolves or loads a proving key. The
generated test relation, keys, and proofs are explicitly non-production; no
relation, key, or ceremony is approved, and this standalone verifier does not
consume a Guardian approval.

The merged verified-preflight boundary,
`jaeger.threat_hint_v2_verified_preflight.ThreatHintV2VerifiedPreflightService`,
composes the two checks without making them authoritative. It owner-loads the
same policy-anchored manifest, runs the Python approval/privacy preflight
first, then invokes an absolute executable pinned by exact SHA-256 and sends
the same exact envelope bytes to `verify-v2` over stdin. The POSIX-only child
is shell-free, environment-scrubbed, time-bounded, process-group-cleaned, and
serialized per service instance. Its receipt is non-constructible,
non-serializable data only. The composition opens no SQLite file, consumes no
approval, and grants no privacy, disclosure, transport, analysis, promotion,
wallet, chain, or rollout authority.

The merged atomic-acceptance boundary,
`jaeger.threat_hint_v2_acceptance.ThreatHintV2AcceptanceService`, closes the
mechanical acceptance order without promoting test artifacts. Construction
requires the preflight and consumption policies to match exactly on network,
approver key, and recipient scope before ledger creation. The public call
accepts only raw envelope, bundle, and approval bytes plus trusted nonce/time,
runs the verified preflight first, and re-verifies the approval ID and
observable commitment before durable consumption runs last. Failed
proof/privacy checks never consume an approval or advance the ledger
high-water. Its non-constructible, non-serializable receipt is data only.
Production relation/key/ceremony approval, independent cryptographic review,
privacy promotion, transport, actionable analysis, signing, chain effects,
and rollout evidence remain separate gates.

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

## 3. Canonical v2 Statement

The local ThreatHint v2 statement is strict UTF-8 JSON with this exact field
order:

```json
{"schema_version":2,"artifact_hash":"0000000000000000000000000000000000000000000000000000000000000000","observable_commitment":"1111111111111111111111111111111111111111111111111111111111111111","confidence_bps":7500,"disclosure_class":"review_required_v1","report_nonce":"2222222222222222222222222222222222222222222222222222222222222222","observed_at":1700000000,"network_id":"testnet-10"}
```

The canonical wire is 1..=1024 bytes. `schema_version` is exact integer `2`.
`artifact_hash`, `observable_commitment`, and `report_nonce` are each exactly
32 bytes encoded as 64 lowercase hexadecimal characters. `confidence_bps` is
an integer in 1..=10000. `disclosure_class` is the closed structural set
`public_auto_v1` or `review_required_v1`; it grants no disclosure authority.
`observed_at` is a positive unsigned 64-bit integer. `network_id` follows the
existing 2..=64-byte lowercase alphanumeric-and-hyphen grammar and must equal a
separately trusted local network argument.

Unknown, duplicate, missing, reordered, alternatively escaped, non-integer,
noncanonical, whitespace-padded, oversized, and trailing input is rejected.
Parsers reserialize and require byte identity. The statement digest is:

```text
SHA256(
  "prometheus-threat-hint-statement-v2\0" ||
  u32be(len(canonical_statement)) || canonical_statement
)
```

This digest structurally binds every field in the canonical statement,
including its distinct artifact hash, observable commitment, report nonce, and
`network_id`. Parser acceptance separately requires `network_id` to equal the
trusted local network; that external context is not part of the digest input.
The digest is not a signature or proof and supplies no replay, privacy,
disclosure, or analysis authority.

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

The closed schema has no field for the following classes, and the structural
validator rejects representations outside the exact kind/value grammars:

- paths, usernames, hostnames, device IDs, process command lines, environment
  values, credentials, tokens, keys, cookies, and connection strings;
- private, loopback, link-local, internal, or unregistered network names and
  addresses;
- unrestricted literals, URLs, registry keys, mutex names, document text, and
  source-code fragments;
- control characters, non-ASCII values, hidden normalization, and values above
  the exact bounds;
- automatic public disclosure of `byte_pattern` entries.

Structural validation cannot prove extractor provenance or semantic privacy.
For example, a string that satisfies the `api_import` token grammar could be
mislabelled by an untrusted producer even if it was not read from a binary
import table. A canonical bundle therefore proves neither that a value came
from the claimed source nor that it is safe to disclose. Producers must accept
observable values only from separately reviewed, kind-specific extractors and
must not expose an arbitrary-string bundle builder to callers. Extractor
allowlists, provenance binding, and privacy review remain promotion gates; the
first local parser must not describe structurally valid input as
`privacy_safe`, `approved`, or equivalent.

The GH-90 producer is the first kind-specific local implementation of this
rule. It accepts exact bytes and typed scope, computes the lowercase SHA-256
value internally, and exposes no path, caller-supplied digest, or generic
observable builder. Its result establishes only deterministic derivation from
the supplied byte slice. It does not prove that those bytes came from a real
file, that the file is malicious, that disclosure is privacy-approved, or that
the digest is bound by a proof. It performs no transport or analysis.

Merged and exact-main-verified GH-94 applies the same bytes-only boundary to one bounded
`byte_pattern`. The caller selects a start offset and a boolean wildcard mask
of 8..=64 positions; every fixed token is derived from the selected artifact
bytes, and at least eight positions must remain fixed. The API accepts no
pattern string and uses checked range arithmetic. Its output is always
`review_required_v1`, so it is structurally valid for local review only and
does not authorize disclosure or transport. Wildcard selection, external
artifact provenance, maliciousness, semantic privacy approval, and proof
binding remain unproved.

GH-103 applies the same no-path/no-arbitrary-value boundary to Linux ELF
imports. The caller supplies exact artifact bytes and a checked index only. A
pinned read-only parser inspects at most 16 MiB and 4096 dynamic symbols,
rejects malformed or non-ELF input and any import outside the closed grammar,
then sorts and deduplicates exact names before selection. Scope is derived as
`linux`/`elf`; every output is `review_required_v1`. The index remains a local
selection, not provenance, maliciousness, privacy approval, disclosure
authorization, or proof binding.

The merged GH-121 Windows PE producer follows the same contract for PE32 and
PE32+ import tables. The pinned read-only parser accepts at most 16 MiB and
4096 import descriptors and 4096 thunk entries, rejects malformed PE, ordinal
imports, and names outside
the closed grammar, then byte-sorts and deduplicates function names before one
checked selection. Scope is fixed to `windows`/`pe`, every output is
`review_required_v1`, and library names never become observable values. This
adds no provenance, privacy approval, disclosure authority, proof binding,
transport, analyzer, wallet, or chain behavior.

`review_required_v1` remains local-only. Any IPC, P2P, Guardian analyzer,
committee, IPFS, chain, or public-rule boundary must reject the complete bundle
even if the sender labels it reviewed. Self-labeling a bundle is never
approval.

Merged and exact-main-verified GH-107 defines and verifies the first local Observable Approval
v1 statement. Its strict canonical JSON field order is:

```text
schema_version, observable_commitment, approver_xonly_public_key, purpose,
recipient_scope, network_id, not_before, expires_at, approval_nonce, signature
```

The wire is capped at 1024 bytes. `schema_version` is integer `1`; `purpose` is
exactly `guardian_analysis_v1`; the commitment, x-only BIP340 public key,
recipient-scope digest, and approval nonce are 32-byte lowercase hexadecimal
values; and the signature is 64-byte lowercase hexadecimal. The trusted local
context supplies the exact report nonce, approver key, recipient-scope digest,
network, and separately trusted current time that must never be
attacker-controlled. The verifier reparses the exact canonical bundle, requires
`review_required_v1`, recomputes its commitment from the trusted network and
report nonce, and compares the trusted key and recipient scope before signature
verification.

The unsigned signing body contains the first nine fields in the order above.
Its 32-byte BIP340 message is:

```text
SHA256(
  "prometheus-observable-approval-v1\0" ||
  u32be(len(canonical_unsigned_body)) || canonical_unsigned_body
)
```

The deterministic approval identifier is:

```text
SHA256(
  "prometheus-observable-approval-id-v1\0" ||
  u32be(len(canonical_full_wire)) || canonical_full_wire
)
```

Validity is inclusive (`not_before <= current_time <= expires_at`), starts
after Unix time zero, and is limited to 3600 seconds. All invalid input returns
one fixed redacted error. The verifier contains no signer and performs no
transport, persistence, promotion, disclosure, analysis, proof, wallet, or
chain action. The signed nonce and approval ID make repeat submissions
identifiable; the verifier alone does not prevent replay.
In Python, the returned object is data only and its object identity is not an
authority boundary.

Merged and exact-main-verified GH-111 adds a separate local Python consumption boundary. It loads one exact
`(network_id, approver_xonly_public_key, recipient_scope)` policy tuple from an
owner-only TOML file, constructs the verification context internally, invokes
the verifier in the same trusted call path, and only then commits the approval
ID plus authority-bound approval nonce to a separate owner-only SQLite ledger.
`BEGIN IMMEDIATE`, unique constraints, full synchronous durability, and a
persistent time high-water make duplicate, concurrent, restarted, and
clock-rollback consumption fail closed. The service never accepts a
caller-supplied verified result, authority key, recipient scope, or network.
Ledger rows grant no downstream authority and trigger no external action.

This local gate does not define approver-key ownership or rotation, explain the
semantics of the opaque recipient-scope digest, authorize disclosure, or
provide exactly-once execution for a future external side effect. GH-117 adds
the separately governed pairing and recoverable local outbox/claim boundaries,
but no bundle may leave the local boundary without future transport and
semantic privacy approval.

The merged ticket-010 promotion boundary closes only the mechanical
hint/bundle/approval pairing and owner-policy restriction above atomic
acceptance. Its exact owner-only policy requires one platform, one format, a
non-empty duplicate-free allowed-kind set, and a 1..=16 count cap. It reparses
the raw canonical bundle and requires `review_required_v1` before the same
original wires may enter proof/privacy verification and durable consumption.
Rejected restrictions never reach the verifier or ledger. This does not prove
semantic privacy, extractor provenance, maliciousness, approver-key ownership,
recipient-scope meaning, production artifact approval, or permission to
transport, analyze, publish, or perform an external effect.

The merged ticket-011 retention-governance boundary adds only a pure,
read-only owner-policy declaration for a possible future recoverable analysis
queue. The exact policy is bound to the expected network, approver key, and
recipient scope and fixes purpose `local_recoverable_analysis_queue_v1`,
payload form `canonical_observable_bundle_v1`, a default-deny durable-kind
allowlist, at most 100,000 pending records, and at most 30 days of retention.
Its risk model is explicit: file hashes remain corpus-matchable, API imports
fingerprint software capabilities, and byte patterns may retain proprietary
content. The loader creates no ledger, outbox, worker, transport, disclosure,
or authority. The merged ticket-013 governed outbox is the only local boundary
that consumes this exact snapshot for a recoverable enqueue.

Ticket 012 composes the promotion, governance, and retention policies into an
enforceable local boundary. The governance policy binds network, approver key,
recipient scope, authority epoch/window, fixed same-Guardian local-analysis
semantics, denied external disclosure, and one explicit per-kind decision.
Every allowed-kind set must be exactly equal before ledger access.

The first valid governed acceptance atomically pins the three exact raw policy
digests, identity, epoch, and authority window with ledger high-water and
approval consumption. Lower epochs, same-epoch digest equivocation,
overlapping same-key/scope windows, hidden legacy authority state, replay, and
failed inserts change no durable state. This still creates no outbox, claim,
worker, transport, disclosure, or actionable analyzer input by itself.

Ticket 014 advances the governed queue to schema v4. One successful governed
promotion stores the canonical statement/digest, trusted report nonce, full
canonical bundle, approval binding, and retention in the exact
`BEGIN IMMEDIATE` transaction that pins or advances authority, moves ledger
high-water, and consumes the approval. Empty v3 queues migrate atomically;
nonempty v3 queues fail closed unchanged because their missing statement and
nonce are unrecoverable.

The owner-local claim API leases the oldest eligible row with an internally
generated opaque 32-byte token, allows recovery after restart or lease expiry,
and caps every lease at the row's retention deadline. Claim reparses the
owner-network statement and bundle, recomputes the nonce-bound commitment, and
derives one identity bound to the exact input, lease, and retention. Atomic
completion stores a canonical explicitly non-actionable result before deleting
the queue row; `acknowledge` cannot bypass result durability. Expired records
are removed at their inherited deadline.

Merged and exact-main-verified GH-152 advances governed durable-outbox ledgers
to schema v5. The promotion
transaction also inserts one permanent strict pairing row whose statement
digest is the primary key and whose approval ID and observable commitment are
independently unique. Outbox and result retention never removes this row, so a
fresh approval cannot rebind a previously accepted statement or commitment.
Only an exact v4 ledger with no retained outbox or result rows migrates to v5;
nonempty v4 state remains unchanged and fails closed because its historical
pairing cannot be reconstructed safely. Legacy and governed non-outbox
consumption retain their prior behavior. This local invariant adds no
production relation, proof, analyzer, transport, disclosure, wallet, chain,
reward, deployment, or external authority.

## 7. Processing Boundary

The safe sequence is:

1. Detect locally and compute `artifact_hash`.
2. Extract only closed observable types.
3. Apply the local deny-by-default policy.
4. Canonicalize and compute `observable_commitment`.
5. Produce a v2 proof only with an approved relation and artifacts.
6. Verify the exact hint and bundle independently at the Guardian.
7. Apply the owner-only platform/format/kind/count promotion restrictions to
   the raw canonical bundle.
8. Verify proof/privacy and durably consume the exact local approval through
   the same governed raw-input acceptance path, atomically pinning or advancing
   the authority snapshot.
9. Atomically enqueue the complete recoverable local analysis payload in the
   same transaction as approval consumption (implemented locally by ticket
   013 for governed promotion only).
10. Produce only the deterministic non-actionable local completion currently
    implemented; real semantic/LLM/YARA analysis requires a separate review.
11. Treat generated rule bytes as potentially public before committee, IPFS, or
   chain submission.

No v1 hint may be silently upgraded, paired with an unbound bundle, or routed
to the existing actionable analyzer.

## 8. Promotion Gates

Implementation may begin with a local canonical bundle type and validator, but
network or analyzer promotion requires:

- frozen cross-language test vectors for valid and invalid canonical bundles
  (implemented locally and exact-main verified by GH-86);
- a canonical authenticated approval statement and cross-language verification
  (implemented locally and exact-main verified by GH-107, without consumption or
  promotion);
- a separate ThreatHint v2 protocol identifier beyond the local statement
  parser (the exact local schema/digest and parity corpus are implemented by
  GH-114 without transport or proof acceptance);
- a reviewed v2 relation source that constrains the exact statement fields;
- independently approved relation, proving/verifying keys, and vectors;
- owner-only durable pairing of one verified hint with one validated bundle;
- local durable one-time approval consumption with trusted fixed policy,
  replay, freshness, size, concurrency, restart, lock, and owner-only storage
  tests (implemented by GH-111 without pairing, promotion, or side effects);
- owner-only exact platform/format/kind/count promotion and raw pairing
  (implemented locally by ticket 010 without semantic privacy authority,
  transport, analysis, or side effects);
- owner-only exact retention declaration for a possible local recoverable
  analysis queue (implemented locally by ticket 011 without persistence,
  runtime, or privacy authority);
- reviewed local authority epoch/window, fixed recipient semantics, exact
  per-kind risk decisions, and atomic anti-rollback policy pinning
  (implemented locally by ticket 012 without worker, transport, or
  production identity attestation);
- a crash-safe atomic recoverable outbox/claim boundary for future actionable
  analysis (implemented locally by ticket 013 without worker execution,
  analyzer invocation, transport, or external effect);
- an independently reviewed bounded outbox worker and real actionable-analysis
  integration;
- privacy review of every observable class and generated-rule publication;
- real multi-host evidence and protected CI/Security/Pages success.

Until those gates pass, verified ThreatHint v1 remains hash-only,
zero-confidence, no-rule, and non-submittable.
