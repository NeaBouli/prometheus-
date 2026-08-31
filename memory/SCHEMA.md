# PROMETHEUS – DATA SCHEMAS
# Kanonische Datenmodelle für das gesamte Projekt.
# Claude Code MUSS diese exakt verwenden. Keine Abweichungen ohne Audit-Approval.
# Last Updated: 2026-07-27

---

## KRITISCHE KLARSTELLUNG: KAS vs. PROM

```
KAS  = Kaspa nativer Token = Staking-Asset der Validators
       → Wird in tx.value gesendet
       → MIN_STAKE_KAS = 10.000 KAS

PROM = Prometheus Token = earned-only Reward-/Governance-Asset
       → Wird durch Leistung VERDIENT
       → Guardians verdienen PROM für akzeptierte Vorschläge
       → NIEMALS als Staking-Asset der Validators verwenden

Guardian-Reputation = separater kanonischer Kaspa-L1-Zustand
       → Wird nicht durch ein Badge/NFT-System ersetzt
       → PROM-Balance und Reputationswert sind nicht dasselbe Feld
```

---

## 1. SILVERSCRIPT SCHEMAS

### 1.1 Validator Struct

```silverscript
struct Validator {
    pubkey: bytes(32),
    stake_kas: uint64,        // ← KAS (NICHT PROM!)
    active: bool,
    joined_at: uint64,        // Unix-Timestamp
    reputation: uint64,       // 0 - 100000 (10000x skaliert, 10000 = 1.0)
    slashing_count: uint64,   // Anzahl Slashing-Events
    last_vote_block: uint64   // Letzter Abstimmungsblock
}

// Konstanten
const MIN_STAKE_KAS: uint64 = 10000;     // KAS
const SLASH_SIMPLE_PCT: uint64 = 5;      // 5% KAS-Verlust
const SLASH_DOUBLE_VOTE_PCT: uint64 = 10; // 10% KAS-Verlust
const SLASH_COLLUSION_PCT: uint64 = 20;  // 20% KAS-Verlust
const COOLDOWN_BLOCKS: uint64 = 100800;  // ~7 Tage bei 10 BPS

// SLASH ESKALATION (nicht-rekursiv, Architect-approved V-003):
// multiplier = min(3, slashing_count / 3 + 1)
// penalty = stake_kas * base_pct * multiplier / 100
// Wenn stake_kas < MIN_STAKE_KAS nach Slashing: validator.active = false
```

### 1.2 Guardian Struct

```silverscript
struct Guardian {
    pubkey: bytes(32),
    compute_power_gflops: uint64, // GFLOPS der GPU
    reputation: uint64,            // 0 - 100000 (10000x skaliert, 10000 = 1.0)
    proposals_submitted: uint64,
    proposals_accepted: uint64,
    registered_at: uint64,
    model_type: uint8             // 0=LLaMA-3-70B, 1=LLaMA-3-8B
}

// Konstanten
const MIN_COMPUTE_GFLOPS: uint64 = 100;  // Minimum Guardian-Hardware
const MIN_REPUTATION: uint64 = 1000;     // 0.1 * 10000 — unter diesem Wert: kein Stimmrecht
const REPUTATION_START: uint64 = 1000;   // 0.1 * 10000 — Startwert für neue Guardians
const REPUTATION_SCALE: uint64 = 10000;  // Skalierungsfaktor: gespeicherter Wert / 10000 = tatsächliche Reputation
```

### 1.3 RuleProposal Struct

```silverscript
struct RuleProposal {
    id: uint64,
    guardian_pubkey: bytes(32),
    threat_hash: bytes(32),       // SHA-256 der Bedrohung
    rule_type: uint8,             // 0=YARA, 1=STIX, 2=Sigma
    rule_content_ipfs: bytes(36), // CIDv1 binary, SHA-256 multihash, 36 bytes (NOT CIDv0/base58)
    confidence: uint64,            // 0 - 10000 (10000x skaliert, 10000 = 1.0)
    submitted_at: uint64,
    votes_for: uint64,
    votes_against: uint64,
    voting_end: uint64,
    status: uint8                 // 0=PENDING, 1=ACCEPTED, 2=REJECTED
}

const MIN_CONFIDENCE: uint64 = 8500;    // 0.85 * 10000 — Mindest-KI-Konfidenz
const VALIDATOR_QUORUM: uint64 = 6700;  // 0.67 * 10000 — 2/3-Mehrheit
const VOTING_BLOCKS: uint64 = 864000;   // ~1 Tag bei 10 BPS
```

### 1.4 VoteCommitment Struct

```silverscript
struct VoteCommitment {
    validator_pubkey: bytes(32),
    proposal_id: uint64,
    commitment: bytes(32),        // sha256(vote_byte || salt_le || block_height_le)
    bond_kas: uint64,             // 10% des Stakes als Kaution
    committed_at_block: uint64
}
```

### 1.5 DevGrant Struct

```silverscript
struct DevGrant {
    id: uint64,
    developer: address,
    contribution_hash: string,    // GitHub Commit/PR URL
    description: string,
    lines_of_code: uint64,
    complexity: uint64,           // 1-10
    requested_amount_prom: uint64,
    votes_for: uint64,
    votes_against: uint64,
    voting_end: uint64,
    executed: bool,
    paid: bool
}

const MAX_GRANT_PROM: uint64 = 100000;  // Max 100k PROM pro Grant
const GRANT_VOTING_PERIOD: uint64 = 604800; // 7 Tage in Sekunden
const REWARD_PER_LINE: uint64 = 10;    // 10 PROM pro Codezeile
```

---

## 2. RUST SCHEMAS

### 2.1 ThreatHintEnvelope v1 (Light Client -> Guardian transport)

```rust
#[serde(deny_unknown_fields)]
pub struct ThreatHintEnvelope {
    schema_version: u16,              // exact 1
    threat_hash: String,              // 32-byte lowercase hex
    confidence_bps: u16,              // 1..=10000, no float on wire
    indicator_type: ThreatIndicatorType,
    proof_system: ThreatProofSystem,
    proof: String,                    // 1..=1024 proof bytes as lowercase hex
    report_nonce: String,             // 32-byte lowercase hex
    observed_at: u64,                 // non-zero Unix timestamp
}

#[serde(rename_all = "snake_case")]
pub enum ThreatIndicatorType {
    FileHash,
    Behavior,
    Network,
    ApiCall,
}

pub enum ThreatProofSystem {
    #[serde(rename = "groth16_kip16_v1")]
    Groth16Kip16V1,
    #[serde(rename = "development_stub_v1")]
    DevelopmentStubV1,
}
```

Canonical JSON field order is `schema_version`, `threat_hash`,
`confidence_bps`, `indicator_type`, `proof_system`, `proof`, `report_nonce`,
`observed_at`. Unknown/duplicate fields, reordered or whitespace-modified bytes,
trailing data, invalid lowercase hex, and envelopes above 2048 bytes fail
closed. No reporter identity, `PeerId`, wallet, chain, membership, reward,
KAS/PROM, slash, or commit-reveal field is transported. GH-58's separate
owner-only Guardian ingress now revalidates these exact bytes, binds the
verifier to trusted local network/domain context, applies persistent
freshness/replay policy, and atomically writes a durable analyzer outbox job.
That job contains canonical wire bytes, digest, network ID, and admission time;
it does not fabricate indicator content absent from this schema. A real
independently approved Groth16 relation, verifying key, and vectors remain
open, so the production verifier is unavailable and returns fail-closed
`busy`.

`threat_hash` is supplied by the v1 client caller. The v1 protocol validates
its shape and statement binding but does not define or verify derivation from a
file or observable. GH-82's normative draft in
`docs/threat-observable-v2.md` therefore leaves v1 unchanged and specifies a
separate `artifact_hash` plus domain-separated
`observable_commitment`. A matching reveal proves commitment consistency only;
GH-114 implements the isolated local canonical schema-2 statement described in
Section 4.4, but no v2 protocol, relation, proof acceptance, pairing, transport,
or analyzer promotion exists.

Merged and exact-main-verified GH-86 implements the local Canonical Observable Bundle v1 parser in Rust and
Python against one shared byte-exact valid/invalid corpus. The local schema is
strict UTF-8 JSON capped at 4096 bytes, carries 1..=16 closed typed
observables, and binds its commitment to the trusted network plus a 32-byte
report nonce. Direct unvalidated construction is excluded from the public
APIs, and value-bearing debug/repr output is disabled. These local types are
not imported by ThreatHint v1, P2P, proof, ingress, analyzer, committee, IPFS,
chain, or public-rule paths. Structural validity proves neither extractor
provenance nor semantic privacy.

Merged and exact-main-verified GH-90 adds one Rust-only producer for exactly one
`file_sha256` observable. Its public inputs are an exact byte slice and typed
platform/format scope; the SHA-256 digest is computed internally and the
digest constructor remains crate-private. Shared vectors bind empty, text, and
binary artifact bytes to the expected digest and canonical wire, which Python
independently validates. This establishes only deterministic derivation from
the supplied bytes and adds no path, transport, proof, analyzer, wallet, or
chain schema.

Merged and exact-main-verified GH-94 adds one Rust-only producer for exactly one
`byte_pattern` observable. It selects 8..=64 positions from exact
caller-supplied bytes using checked offset arithmetic and a same-length boolean
wildcard mask, requires at least eight fixed positions, and accepts no pattern
string. Its crate-private constructor accepts fixed-or-wildcard byte tokens,
not arbitrary observable text. The bundle is always `review_required_v1` and
remains local-only; no transport, approval envelope, proof, analyzer, wallet,
or chain schema is added.

GH-103 adds one Rust-only producer for one Linux ELF `api_import`. Public
inputs are exact artifact bytes plus a checked index into the byte-sorted,
deduplicated dynamic-import names. Scope is fixed internally to `linux`/`elf`;
the parser accepts at most 16 MiB and inspects at most 4096 dynamic symbols.
Malformed/non-ELF input and names outside the existing closed grammar fail
with fixed errors. The resulting bundle is always `review_required_v1`;
no path/string/generic builder, wire, approval envelope, proof, analyzer,
wallet, or chain schema is added.

Merged and exact-main-verified GH-121 adds no new wire kind or schema. It
produces the existing `api_import` kind from exact PE32/PE32+ bytes plus one
checked index, fixes scope to `windows`/`pe`, caps input at 16 MiB and both
descriptors and thunk entries at 4096, and rejects malformed descriptors,
ordinal imports, or names
outside the same closed grammar. Library names are never observable values.
Every output remains `review_required_v1`; no path, arbitrary string,
transport, approval, proof, analyzer, wallet, chain, or promotion schema is
introduced.

Merged and exact-main-verified GH-107 adds a local Observable Approval v1 envelope and matching
Rust/Python verification only. Canonical field order is `schema_version`,
`observable_commitment`, `approver_xonly_public_key`, `purpose`,
`recipient_scope`, `network_id`, `not_before`, `expires_at`,
`approval_nonce`, `signature`; the full wire is capped at 1024 bytes.
Fixed-size fields use lowercase hex, purpose is `guardian_analysis_v1`, and the
BIP340 message is SHA-256 over
`prometheus-observable-approval-v1\0 || u32be(body_len) || canonical_body`.
The deterministic ID uses the separate
`prometheus-observable-approval-id-v1\0` domain over the full canonical wire.
Validity is inclusive and capped at 3600 seconds. Verification requires a
separately trusted report nonce, approver key, recipient-scope digest, network,
and current time; the current time must never be attacker-controlled. The
verifier recomputes the exact review-required bundle commitment.
No signer, replay ledger, transport, promotion, analyzer, proof, wallet, or
chain schema is introduced. The nonce/ID make repeats identifiable but do not
prevent replay.

GH-111 adds a separate local Guardian persistence schema, not a protocol wire:

```text
approval_consumptions(
  approval_id BLOB(32) PRIMARY KEY,
  approver_xonly_public_key BLOB(32),
  approval_nonce BLOB(32),
  observable_commitment BLOB(32),
  recipient_scope BLOB(32),
  network_id TEXT,
  not_before INTEGER,
  expires_at INTEGER,
  consumed_at INTEGER,
  UNIQUE(approver_xonly_public_key, approval_nonce)
)
ledger_state(singleton = 1, high_water_seconds INTEGER)
```

The exact-schema owner-only TOML policy fixes `schema_version = 1`,
`network_id`, `approver_xonly_public_key`, `recipient_scope`, and an absolute
`ledger_path`. This schema is local replay state only. It does not define a v2
network message, approver rotation, recipient-scope semantics, verified
hint/bundle pairing, promotion, analyzer/outbox behavior, proof, wallet, or
chain state.

### 2.2 ScanResult (Phi-3-mini Output)

```rust
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub path: PathBuf,
    pub file_hash: [u8; 32],
    pub threat_score: f64,           // 0.0 - 1.0
    pub confidence: f64,
    pub threat_type: Option<String>,
    pub scan_duration_ms: u64,
    pub quarantine_recommended: bool,
}
```

### 2.3 KaspaRule (On-Chain Regel, gelesen von L1)

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct KaspaRule {
    pub rule_id: String,             // "PROM-RULE-2026-XXXX"
    pub rule_type: RuleType,
    pub ipfs_cid: String,            // IPFS CID des Regelinhalts
    pub guardian_id: [u8; 32],
    pub validator_consensus: f64,    // 0.0 - 1.0
    pub timestamp: u64,
    pub active: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub enum RuleType {
    Yara,
    Stix,
    Sigma,
    Suricata,
}
```

### 2.4 Implemented P2P request types

```text
/prometheus/guardian-ballot/1.0.0 request = BallotBytes
/prometheus/threat-hint/1.0.0 request = ThreatHintEnvelope
```

These are independent libp2p request-response behaviours with separate request
IDs, response channels, and work maps under shared global admission and stream
budgets. The earlier generic TCP `NetworkMessage`/handshake design is not an
implemented protocol. Rule updates, proposal transport, and subscriptions
remain open.

---

## 3. PYTHON SCHEMAS (Guardian-Node)

### 3.1 ThreatAnalysis (LLaMA Output)

```python
@dataclass
class ThreatAnalysis:
    threat_hints: List[ThreatHint]    # Eingabe
    yara_rule: str                     # Generierte YARA-Regel
    confidence: float                  # 0.0 - 1.0
    threat_family: str                 # z.B. "Pegasus", "Predator"
    affected_os: List[str]             # ["windows", "macos", "linux"]
    cve_references: List[str]          # CVE-IDs
    ioc_patterns: List[str]            # Indicators of Compromise
    analysis_duration_ms: int
```

### 3.2 Guardian verified ThreatHint v1 analyzer input

```python
@dataclass(frozen=True)
class VerifiedThreatHint:
    payload_digest: str                # SHA-256 of exact canonical wire
    schema_version: int                # exact 1
    threat_hash: str                   # verified 32-byte lowercase hex
    confidence_bps: int                # verified source claim, 1..10000
    indicator_type: str                # category metadata, not an IOC value
    proof_system: str                  # exact groth16_kip16_v1
    reporter_zk_proof: bytes           # verified bounded proof bytes
    report_nonce: str                  # verified 32-byte lowercase hex
    observed_at: int                   # verified/fresh Unix timestamp
    network_id: str                    # trusted local network context
    admitted_at: int                   # durable ingress admission time
```

This Python dataclass is not the wire parser. GH-74's adapter re-parses the
canonical bytes and revalidates digest, trusted network, proof mode, and
admission window before constructing it. It intentionally has no `indicators`
field because ThreatHint v1 does not transport concrete IOC strings. The
verified-v1 analyzer path must return zero confidence, no YARA rule, and no
submission without invoking an LLM. The older local `ThreatHint` type with
explicit indicator strings remains a separate manually constructed analyzer
input and is never populated by this adapter.

### 3.3 Authenticated Guardian Ballot (GH-39)

The session commitment binds the signed-ballot protocol version, network ID,
candidate digest, membership snapshot ID, session nonce, validity window, and
the exact sorted set of unique `(guardian_id, xonly_public_key)` entries.

The exact-schema canonical JSON envelope contains:

```text
protocol_version, vote_protocol_version, session_id, network_id,
guardian_id, membership_snapshot_id, candidate_digest, decision,
confidence_bps, model_tier, model_artifact_sha256, nonce,
issued_at_ms, expires_at_ms, payload_digest, signature
```

The owner-only SQLite replay ledger stores the canonical wire bytes plus
`session_valid_until_ms`, maintains a singleton monotonic `high_water_ms`, and
enforces:

```sql
PRIMARY KEY (session_id, guardian_id)
UNIQUE (session_id, nonce)
```

Markers may be removed only after the complete session expires. The parent
directory must be owner-controlled, the regular database file is mode `0600`,
symlink paths are rejected, and a wall-clock rollback below the persisted
high-water mark fails closed. Membership/key trust, Sybil resistance, and
on-chain attestation are not properties of this schema.

### 3.4 Guardian Ballot Carrier (GH-42)

The libp2p stream is versioned independently as
`/prometheus/guardian-ballot/1.0.0`:

```text
request  = uint16_be(length) || exact SignedGuardianBallot bytes
response = uint8(status)  # accepted=0, duplicate=1, rejected=2, busy=3
```

`length` must be in `1..=8192`. The local AF_UNIX bridge uses a four-byte
big-endian length around the same exact ballot bytes and a canonical JSON ACK
containing protocol version, session ID, payload SHA-256, and status. The Rust
side verifies socket ownership/peer credentials and the ACK digest before
answering the remote request. No PeerId, address, relay, or route field enters
the Guardian membership/session schema.

### 3.5 Guardian Transport Identity and Routes (GH-44 merged)

The libp2p transport identity is a canonical bounded private-key protobuf in an
owner-controlled local file. Its public `PeerId` is transport metadata only and
must never enter Guardian membership, BIP340 key assignment, reputation,
staking, reward, or chain-state records.

Accepted operator routes are closed schemas rather than arbitrary strings:

```text
direct listen = /ip4|ip6/<ip>/udp/<port>/quic-v1
direct peer   = direct listen [/p2p/<target-peer-id>]
relay listen  = direct peer-of-relay /p2p-circuit
relay peer    = relay listen /p2p/<target-peer-id>
AutoNAT       = direct peer route only
```

Counts and encoded address length are bounded. DNS/mDNS, target-mismatched,
duplicate, unspecified dial, and zero-port dial routes fail validation.

### 3.6 Guardian Operated Service Boundary (GH-48 merged)

The strict service config is role-tagged TOML. Both roles require an absolute
persistent transport-identity path and bounded listener set. Guardian adds
distinct absolute collector/submission sockets, optional bounded static and
AutoNAT routes, bounded health/ingress/startup/drain durations, and bounded
local admission. Relay accepts no Guardian collector, submission, membership,
wallet, reputation, or token fields. Unknown fields fail parsing.

The owner-only local submission frame is:

```text
u8 version | u16 peer_id_length | canonical PeerId UTF-8 |
u32 ballot_length | exact opaque ballot bytes | EOF
```

The response is `u8 version | u8 status | EOF`. Ballots remain capped at 8192
bytes. JSON operator records may contain transport peer/address/path/status and
bounded counts, but never ballot bytes, collector ACK bytes, or filesystem
paths. Records are serialized before entering a bounded dedicated stdout queue;
queue saturation or writer failure is terminal, and `stopped` is emitted only
after the local submission server confirms shutdown. None of these fields enter
Guardian membership/session, reputation, staking, reward, or Kaspa state
schemas.

---

## 4. API DATENSTRUKTUREN (JSON)

### 4.1 Client → Guardian: Bedrohungsmeldung

```json
{
  "type": "threat_hint",
  "version": 1,
  "file_hash": "sha256:3f7cb77b...",
  "confidence": 0.91,
  "indicator_type": "file_hash",
  "zk_proof": "<base64-encoded-groth16-proof>",
  "reporter_id": "<anonymized-hash>",
  "timestamp": 1762531200
}
```

### 4.2 Guardian → Validator: Regelvorschlag

```json
{
  "type": "rule_proposal",
  "version": 1,
  "proposal_id": "<uuid>",
  "threat_hash": "sha256:3f7cb77b...",
  "rule_type": "yara",
  "rule_ipfs_cid": "bafybei...",
  "confidence": 0.94,
  "guardian_signature": "<ed25519-sig>",
  "timestamp": 1762531202
}
```

### 4.3 L1 → Client: Finale Regel (KRC20 Metadata)

```json
{
  "tick": "PROM-RULES",
  "rule_id": "PROM-RULE-2026-0001",
  "rule_type": "yara",
  "ipfs_cid": "bafybei...",
  "guardian_id": "<guardian-hash>",
  "validator_consensus": 0.89,
  "timestamp": 1762531235,
  "active": true
}
```

### 4.4 Local ThreatHint v2 Statement (GH-114)

The isolated local canonical statement is exact UTF-8 JSON:

```text
schema_version: exact integer 2
artifact_hash: 64 lowercase hex characters
observable_commitment: 64 lowercase hex characters
confidence_bps: integer 1..=10000
disclosure_class: public_auto_v1 | review_required_v1
report_nonce: 64 lowercase hex characters
observed_at: positive u64
network_id: 2..=64 lowercase alphanumeric/hyphen bytes
```

These fields appear in exactly that order and the complete wire is at most 1024
bytes. The wire network must equal a separately trusted local network. Unknown,
duplicate, missing, reordered, alternatively encoded, non-integer, trailing,
or oversized input fails with one redacted error.

The statement digest is
`SHA256("prometheus-threat-hint-statement-v2\0" || u32be(wire_len) || wire)`.
It binds the exact fields structurally but is not a signature, proof, replay
ledger, privacy decision, approval, disclosure grant, or analyzer input.
ThreatHint v1 schema, relation, verifier, transport, and analyzer types remain
unchanged.

### 4.5 Merged GH-117 local ThreatHint v2 proof envelope, manifest, and binding

The proof envelope is exact canonical JSON with six ordered fields:
`schema_version`, `protocol_id`, `relation_id`, embedded canonical `statement`,
`statement_digest`, and lowercase opaque `proof`. It is capped at 4096 bytes;
proof bytes are bounded to 1..1024 and are never interpreted.

`RelationManifest-v2` is exact canonical JSON with 19 ordered fields binding
schema, protocol, relation, statement-digest domain, proof-system identity,
KIP-16 tag, public-input encoding/count, network, relation-source size/hash,
proving-key size/hash, verifying-key size/hash, KIP-16 status commit,
rusty-kaspa tag/commit, and Arkworks version. The canonical wire is capped at
4096 bytes. Relation/key hashes and sizes are inert assertions.

`bind_canonical(envelope_wire, manifest_wire, trusted_network_id,
trusted_manifest_sha256_hex)` requires exact built-in byte/string types,
validates the trusted context, hashes the raw manifest before parsing, reparses
both canonical objects, recomputes the statement digest from the
manifest-declared domain, and splits the 32-byte digest into two 16-byte
big-endian claimed inputs for `sha256_split_u128_bn254_v2`.

The shared binding corpus has 5 valid and 28 invalid cases. This boundary
defines structural compatibility only; it is not a Groth16 verifier, artifact
approval, transport wire, analyzer input, promotion receipt, or rollout state.

### 4.6 Local ThreatHint v2 Privacy/Proof Preflight Candidate

The owner-only read-only policy is exact TOML:

```toml
schema_version = 1
network_id = "testnet-10"
approver_xonly_public_key = "<64 lowercase hex characters>"
recipient_scope = "<64 lowercase hex characters>"
relation_manifest_sha256 = "<64 lowercase nonzero hex characters>"
```

It contains no ledger path. The public preflight accepts exact envelope,
manifest, bundle, and approval bytes plus a trusted 32-byte report nonce and
positive u64 current time. It derives the statement only from the bound
envelope and returns a frozen data object containing the 32-byte statement
digest, approval ID, observable commitment, raw manifest SHA-256, and exact
envelope SHA-256.

No table or durable receipt is added. The schema represents neither proof
acceptance nor privacy/disclosure authority and cannot authorize transport,
analysis, promotion, wallet, chain, reputation, token, slash, or
commit-reveal behavior.

### 4.7 Local ThreatHint v2 Trusted Verifier Bundle Candidate

The verifier bundle directory has three owner-only files:

```text
relation-manifest-v2.json  # exact path supplied with separately trusted hash
relation-source.bin        # fixed sibling; exact manifest size/SHA-256
verifying-key.bin          # fixed sibling; exact manifest size/SHA-256
```

The manifest filename itself is operator-selected but its absolute canonical
path and raw SHA-256 are trusted configuration. The two artifact filenames are
code-fixed. The directory and files must be owned by the effective user,
non-symlink regular objects with no group/other permissions; the existing
owner-file loader pins open-file device/inode identity and enforces declared
size caps.

No `proving-key.bin` runtime file exists or is consulted. Manifest proving-key
size/hash fields remain inert ceremony metadata. A successful `verify-v2`
status means only that one canonical proof verifies under the locally pinned
verifying key for the two inputs derived by the v2 binding. It is not a
durable receipt, privacy approval, artifact/ceremony approval, or rollout
state.

### 4.8 Local ThreatHint v2 Verified-Preflight Candidate

The owner-only configuration is exact ASCII TOML:

```toml
schema_version = 1
verifier_executable_path = "/absolute/path/to/prometheus-threat-proof"
verifier_executable_sha256 = "<64 lowercase nonzero hex characters>"
relation_manifest_path = "/absolute/path/to/relation-manifest-v2.json"
verifier_timeout_ms = 30000
```

Only these five fields are accepted. Both paths must be absolute canonical
non-symlink paths under ancestors owned by the current user or root with no
group/world write permission. The manifest and config are owner-only regular
files capped at 4096 bytes. The executable must be an owner-executable regular
file without set-id or group/world write bits, is capped at 64 MiB, and is
rehashed before every invocation.

The frozen data-only receipt has exactly:

```text
statement_digest: 32 bytes
approval_id: 32 bytes
observable_commitment: 32 bytes
raw_manifest_sha256_hex: 64 lowercase hex characters
envelope_sha256_hex: 64 lowercase hex characters
verifier_executable_sha256_hex: 64 lowercase hex characters
```

Construction and serialization are disabled. The receipt is neither durable
state nor an authority object. No database schema, migration, approval
consumption, production artifact approval, privacy/disclosure grant, transport
admission, analyzer input, chain acceptance, or rollout status is added.

### 4.9 Local ThreatHint v2 Atomic Acceptance Candidate

The acceptance service introduces no new persistent schema. It reuses the
existing owner-only Observable Approval policy and SQLite schema version 1.
The preflight and consumption policies must match exactly on:

```text
network_id: closed protocol network identifier
approver_xonly_public_key: exactly 32 bytes
recipient_scope: exactly 32 opaque bytes
```

Mismatch fails before ledger creation or open. The final consumption receives
only the raw approval/bundle plus the preflight-derived expected 32-byte
`approval_id` and 32-byte `observable_commitment`; both are re-verified and
compared before the existing `BEGIN IMMEDIATE` insert.

The frozen data-only acceptance receipt has exactly:

```text
statement_digest: 32 bytes
approval_id: 32 bytes
observable_commitment: 32 bytes
consumed_at: trusted uint64-compatible time
raw_manifest_sha256_hex: 64 lowercase hex characters
envelope_sha256_hex: 64 lowercase hex characters
verifier_executable_sha256_hex: 64 lowercase hex characters
```

Construction, replacement, and serialization are disabled. This receipt is
not a privacy grant, transport admission, analyzer input, artifact approval,
chain record, or rollout status.

### 4.10 Local ThreatHint v2 Owner-Policy Promotion Candidate

The exact owner-only ASCII TOML policy has only:

```toml
schema_version = 1
scope_platform = "linux"
scope_format = "elf"
allowed_observable_kinds = ["api_import", "file_sha256"]
max_observables = 4
```

`scope_platform` and `scope_format` use the existing closed enums.
`allowed_observable_kinds` is non-empty, duplicate-free, and contains only
existing closed observable kinds. `max_observables` is an exact integer in
`1..=16`. The schema deliberately repeats no network, approver key, recipient
scope, manifest, relation, or ledger authority.

The frozen data-only promotion result has exactly:

```text
statement_digest: 32 bytes
approval_id: 32 bytes
observable_commitment: 32 bytes
consumed_at: trusted uint64-compatible time
scope_platform: canonical enum string
scope_format: canonical enum string
observables: immutable ordered tuple of canonical (kind, value) strings
```

Construction, replacement, and serialization are disabled. The result is not
semantic privacy approval, authority/key governance, transport admission,
analyzer input, publication permission, artifact approval, external-effect
receipt, chain record, or rollout state.

### 4.11 Local Outbox Retention-Governance Candidate

The exact owner-only ASCII TOML policy has only:

```toml
schema_version = 1
network_id = "testnet-10"
approver_xonly_public_key = "<64 lowercase hex characters>"
recipient_scope = "<64 lowercase hex characters>"
retention_purpose = "local_recoverable_analysis_queue_v1"
payload_form = "canonical_observable_bundle_v1"
durable_observable_kinds = ["file_sha256", "api_import"]
max_pending_records = 10000
max_retention_seconds = 604800
```

The identity tuple must exactly equal separately expected values.
`durable_observable_kinds` is non-empty, duplicate-free, and contains only the
closed observable kinds. `max_pending_records` is an exact integer in
`1..=100000`; `max_retention_seconds` is an exact integer in `1..=2592000`.
File hashes remain corpus-matchable, API imports fingerprint software
capabilities, and byte patterns may retain proprietary content.

This declaration introduces no database schema, migration, outbox table,
ledger row, queue item, worker, disclosure, or transport. A future recoverable
enqueue must share the existing `BEGIN IMMEDIATE` transaction with approval
consumption and ledger high-water; a digest-only journal is not a recoverable
payload.

### 4.12 Governed Approval Ledger Schema v2

Ticket 012 migrates the existing owner-only approval ledger from schema v1 to
v2 without changing `approval_consumptions` or `ledger_state`. The new strict
singleton table is:

```sql
CREATE TABLE authority_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    authority_epoch INTEGER NOT NULL CHECK (authority_epoch >= 1),
    governance_policy_sha256 BLOB NOT NULL
        CHECK(length(governance_policy_sha256) = 32),
    retention_policy_sha256 BLOB NOT NULL
        CHECK(length(retention_policy_sha256) = 32),
    promotion_policy_sha256 BLOB NOT NULL
        CHECK(length(promotion_policy_sha256) = 32),
    network_id TEXT NOT NULL,
    approver_xonly_public_key BLOB NOT NULL
        CHECK(length(approver_xonly_public_key) = 32),
    recipient_scope BLOB NOT NULL
        CHECK(length(recipient_scope) = 32),
    authority_not_before INTEGER NOT NULL,
    authority_not_after INTEGER NOT NULL
) STRICT;
```

Migration requires the v1 schema to validate exactly and rejects any
pre-existing `authority_state`. The new table starts empty. First valid
governed consumption inserts the snapshot; a higher epoch updates it only in
the same `BEGIN IMMEDIATE` transaction as high-water and the consumption row.
Lower epochs and same-epoch digest or identity/window changes fail. With an
unchanged key and scope, a new epoch must start strictly after the prior
inclusive window; key or scope rotation may overlap.

Authority instants follow the protocol uint64 domain. SQLite integers are
signed 64-bit; a farther-future value above `2^63-1` is therefore rejected
fail-closed during atomic persistence with a redacted error and rollback.

### Governed approval ledger schema v3 (Ticket 013)

Only governed ledgers migrate to schema v3. Legacy consumption remains schema
v1. Migration from governed v0/v1/v2 preserves `approval_consumptions`,
`ledger_state`, and `authority_state`; a hidden preexisting outbox or attempted
downgrade fails closed.

```sql
CREATE TABLE approval_outbox (
    approval_id BLOB PRIMARY KEY CHECK(length(approval_id) = 32),
    observable_commitment BLOB NOT NULL
        CHECK(length(observable_commitment) = 32),
    bundle_wire BLOB NOT NULL CHECK(length(bundle_wire) >= 1),
    enqueued_at INTEGER NOT NULL CHECK(enqueued_at >= 1),
    retention_deadline INTEGER NOT NULL
        CHECK(retention_deadline >= enqueued_at),
    lease_token BLOB CHECK(
        lease_token IS NULL OR length(lease_token) = 32
    ),
    lease_expires_at INTEGER
        CHECK(lease_expires_at IS NULL OR lease_expires_at >= 1),
    CHECK((lease_token IS NULL) = (lease_expires_at IS NULL)),
    CHECK(
        lease_expires_at IS NULL
        OR lease_expires_at <= retention_deadline
    )
) STRICT;
```

Capacity check and enqueue run inside the same `BEGIN IMMEDIATE` transaction
as authority state, ledger high-water, and approval consumption. Claim removes
expired-retention rows, selects the oldest pending or expired-lease row, and
sets an internal 32-byte token plus retention-bounded expiry atomically.
Acknowledge deletes only the exact approval-ID/token row. Application
validation additionally enforces the canonical bundle's 4096-byte protocol
cap both before enqueue and when reading a claimed row.

### Governed approval ledger schema v4 (Ticket 014)

Governed v0/v1/v2 ledgers migrate losslessly. A v3 ledger migrates only when
`approval_outbox` is empty; a nonempty v3 queue remains unchanged and fails
closed because its statement and report nonce cannot be recovered. Legacy
non-governed consumption remains schema v1.

Schema v4 extends `approval_outbox` with:

```sql
statement_wire BLOB NOT NULL CHECK(length(statement_wire) >= 1),
statement_digest BLOB NOT NULL CHECK(length(statement_digest) = 32),
report_nonce BLOB NOT NULL CHECK(length(report_nonce) = 32)
```

It also adds:

```sql
CREATE TABLE observable_analysis_results (
    approval_id BLOB PRIMARY KEY
        CHECK(length(approval_id) = 32)
        REFERENCES approval_consumptions(approval_id),
    result_wire BLOB NOT NULL CHECK(length(result_wire) >= 1),
    result_digest BLOB NOT NULL CHECK(length(result_digest) = 32),
    input_identity BLOB NOT NULL CHECK(length(input_identity) = 32),
    completion_token_digest BLOB NOT NULL
        CHECK(length(completion_token_digest) = 32),
    completed_at INTEGER NOT NULL CHECK(completed_at >= 1),
    retention_deadline INTEGER NOT NULL
        CHECK(retention_deadline >= completed_at)
) STRICT;
```

Foreign-key enforcement is enabled on every connection. Completion inserts one
result and deletes the leased outbox row in the same transaction. The result
references the persistent consumption row, so it survives outbox deletion.
Its deadline is inherited from the original outbox record and bound into both
the lease input identity and the result-record digest.

### Governed approval ledger schema v5 (GH-152)

Schema v5 preserves every v4 table and adds:

```sql
CREATE TABLE threat_hint_v2_pairings (
    statement_digest BLOB PRIMARY KEY CHECK(length(statement_digest) = 32),
    approval_id BLOB NOT NULL UNIQUE
        CHECK(length(approval_id) = 32)
        REFERENCES approval_consumptions(approval_id),
    observable_commitment BLOB NOT NULL UNIQUE
        CHECK(length(observable_commitment) = 32),
    network_id TEXT NOT NULL,
    consumed_at INTEGER NOT NULL CHECK(consumed_at >= 1)
) STRICT;
```

Durable governed promotion inserts this row in the same `BEGIN IMMEDIATE`
transaction as authority, high-water, approval consumption, and outbox enqueue.
The table is permanent and is never subject to outbox/result retention.
Empty exact v4 databases migrate to v5; nonempty v4 outbox or result state
fails closed unchanged. Legacy schema v1 remains unchanged.

**GH-152 migration clarification (2026-08-09):** "empty v4" applies only to
`approval_outbox` and `observable_analysis_results`. Authority state, ledger
high-water, and approval-consumption rows are preserved by migration. Any row in
either gated table keeps the whole v4 database unchanged and fails closed.

### Semantic draft result wire v2 (GH-173)

Ledger schema v5 and the seven-column `observable_analysis_results` table remain
unchanged. `result_wire` is an opaque bounded BLOB, so GH-173 is a wire-version
extension rather than a SQLite migration.

Canonical v2 fields, in exact order, are the eight v1 binding/count fields plus
`observable_kind_counts`, `candidate_binding_sha256`, and `rule_compile_ok`.
`observable_kind_counts` itself has exactly ordered `file_sha256`, `api_import`,
and `byte_pattern` integer fields whose sum equals `observable_count`. The
candidate binding is one nonzero lowercase 32-byte SHA-256 over a fixed domain,
the approved report nonce, and the transient raw candidate digest. Compile status
is an exact boolean. Existing canonical v1 wires remain accepted on read and
completion retry. No rule source or observable value is stored in this result.

### Guardian membership continuity ledger v1 (GH-246)

The owner-only SQLite ledger has exact STRICT singleton tables for immutable
network/authority/bootstrap anchors, current epoch/digest/canonical source
bytes, and trusted-clock high-water, plus transition history uniquely keyed by
transition ID, nonce, and next epoch. Applying a verified transition inserts
history and replaces current source/epoch/high-water in one `BEGIN IMMEDIATE`
transaction. The schema stores public source/signature evidence only and no
private key.
