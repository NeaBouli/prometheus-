# PROMETHEUS – DATA SCHEMAS
# Kanonische Datenmodelle für das gesamte Projekt.
# Claude Code MUSS diese exakt verwenden. Keine Abweichungen ohne Audit-Approval.
# Last Updated: 2026-07-16

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
future separate `artifact_hash` plus domain-separated
`observable_commitment`. A matching reveal proves commitment consistency only;
no v2 wire schema is implemented yet.

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
