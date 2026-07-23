# PROMETHEUS – API DEFINITIONEN
# Stabile Schnittstellen-Definitionen für alle Module.
# Änderungen hier erfordern einen Audit durch Claude.
# Last Updated: 2026-07-16

---

## 1. KASPA RPC API (rusty-kaspa)

### Verbindung

```rust
// Testnet
const TESTNET_RPC: &str = "ws://127.0.0.1:16210";
const MAINNET_RPC: &str = "ws://127.0.0.1:16110";

// Verbindung aufbauen
let client = RpcClient::connect(rpc_url, NetworkId::with_suffix(NetworkType::Testnet, 10)).await?;
```

### Wichtige Endpoints

```rust
// Aktuellen Block holen
client.get_block_dag_info().await?

// KRC20-Assets (Regeln) lesen
client.get_utxos_by_addresses(vec![rule_address]).await?

// Transaktion senden (Regel einreichen)
client.submit_transaction(tx, false).await?

// Block-Updates abonnieren
client.subscribe_block_added().await?
```

---

## 2. LIGHT CLIENT INTERNAL API

### Scanner Interface

```rust
pub trait SecurityScanner: Send + Sync {
    async fn scan_file(&self, path: &Path) -> Result<ScanResult>;
    async fn scan_directory(&self, path: &Path) -> Result<Vec<ScanResult>>;
    fn update_rules(&self, rules: Vec<KaspaRule>) -> Result<()>;
    fn get_active_rules_count(&self) -> usize;
}
```

### Blockchain Interface (target, not implemented)

```rust
pub trait BlockchainClient: Send + Sync {
    async fn connect(&self) -> Result<()>;
    async fn get_latest_rules(&self) -> Result<Vec<KaspaRule>>;
    async fn get_prom_balance(&self, address: &Address) -> Result<u64>;
    fn is_connected(&self) -> bool;
}
```

ThreatHints are not Kaspa transactions. GH-55 defines an independent bounded
libp2p transport channel; accepted Guardian ingestion and any later proposal or
reward flow remain separate and unimplemented.

### AI Interface

```rust
pub trait LocalAI: Send + Sync {
    async fn analyze_file(&self, path: &Path) -> Result<ScanResult>;
    async fn generate_zk_proof(&self, data: &[u8]) -> Result<Vec<u8>>;
    async fn participate_in_federated_learning(&self) -> Result<()>;
    fn get_model_version(&self) -> String;
}
```

---

## 3. GUARDIAN NODE API

### HTTP API (target only, not implemented)

```
POST /api/v1/threat-hint
  Body: ThreatHint (JSON)
  Response: { "received": true, "proposal_id": "uuid" }

GET /api/v1/status
  Response: { "model": "llama3-8b|70b", "reputation": 0.95, "proposals_today": 12 }

GET /api/v1/proposals
  Response: List<RuleProposal>
```

### Python Interface

```python
class GuardianNode:
    async def receive_threat_hint(self, hint: ThreatHint) -> None
    async def analyze_threats(self, hints: List[ThreatHint]) -> ThreatAnalysis
    async def submit_proposal(self, analysis: ThreatAnalysis) -> str  # returns proposal_id
    async def get_reputation(self) -> float
```

### Local Ensemble Interface (GH-36)

```python
candidate = EnsembleCandidate.create(rule, policy_sha256, model_artifact_sha256)
snapshot = MembershipSnapshot.create(members, membership_source_sha256)
decision = EnsembleVoter().evaluate(candidate, snapshot, votes)
```

`decision.analysis.should_submit` is true only for a complete ballot from at
least five unique 8B members with a strict majority. The candidate and snapshot
are domain-separated commitments; source-rule and approve confidence use exact
integer basis points with a minimum of `8500`, and the result uses the minimum
confidence. By itself, this local API does not establish membership trust,
authenticate or transport votes, prevent replay/Sybil identities, submit a
proposal, or create an on-chain ensemble proof.

### Authenticated Ballot Intake (GH-39)

```python
session = BallotSession.create(
    candidate,
    snapshot,
    signers,
    network_id,
    session_nonce,
    valid_from_ms,
    valid_until_ms,
)
request = BallotSigningRequest.create(
    vote, candidate, snapshot, session, nonce, issued_at_ms, expires_at_ms
)
envelope = request.attach_signature(external_public_signature)

collector = AuthenticatedBallotCollector(ReplayLedger(owner_only_db_path))
collector.accept_wire(envelope.to_wire(), candidate, snapshot, session, now_ms)
decision = collector.evaluate(candidate, snapshot, session, now_ms)
```

The request exports only a domain-separated 32-byte digest; an external signer
returns a public 64-byte BIP340 signature. Production code accepts no private
key. Exact canonical JSON binds the complete vote/session/network/time context.
The owner-only SQLite ledger atomically enforces unique
`(session_id, guardian_id)` and `(session_id, nonce)` pairs across restart and
concurrency, retains markers through session expiry, and reverifies stored
envelopes before calling the unchanged `EnsembleVoter`. A persistent monotonic
ledger-time watermark rejects wall-clock rollback after pruning.

### Guardian Ballot Carrier (GH-42)

The Rust `prometheus-guardian-p2p` crate exposes `GuardianP2p`,
`BallotBytes`, `UnixBallotIngress`, and the production seam
`next_sidecar_event()`. Direct QUIC request/response transports one exact
opaque frame under `/prometheus/guardian-ballot/1.0.0`; the 8192-byte frame
limit, connection/stream/request caps, and timeouts apply before the local
collector. The AF_UNIX client requires the directory, socket, and connected
peer credentials to match the sidecar effective UID. Canonical local ACKs bind
the exact SHA-256 payload digest before the network receives a one-byte status.

Static peer addresses and relay/AutoNAT/DCUtR behaviours are implemented.
Operated relay/NAT/discovery, trusted membership/key assignment, Sybil
resistance, proposal submission, and on-chain attestation remain outside this
API. `PeerId` is never Guardian authorization.

### Guardian Operated Transport Candidate (GH-44)

`transport_identity::load_or_create_transport_identity()` requires an absolute
path and an effective-user-owned mode-`0700` parent directory. It rejects
symlinks, non-regular files, unsafe ownership/mode, oversized or noncanonical
protobuf, writes a mode-`0600` same-directory temporary file, syncs it, and
publishes atomically. Concurrent creators converge on one stable transport
`PeerId`; no wallet or Guardian signing key is involved.

`GuardianP2pConfig` accepts bounded direct IP/UDP/QUIC-v1 listeners and exact
relay reservations ending in `/p2p-circuit`, plus direct static routes, exact
relay-circuit routes, and explicit direct AutoNAT servers. DNS and mDNS routes
are rejected. `RelayService` applies fixed
reservation, circuit, byte, duration, connection, and per-peer limits. Health
events expose only transport peer/path/status metadata. The isolated three-node
test proves reservation, relayed ballot/ACK, AutoNAT state, DCUtR failure with
relay fallback, and disconnect handling. Public or multi-host operation, broad
discovery, membership trust, and on-chain attestation remain outside this API.

### Guardian Operated Service (GH-48 merged)

The `prometheus-guardian-p2p` binary exposes `preflight --config`,
`run --config`, and `submit --socket --peer --ballot`. Role-tagged TOML is
bounded, rejects unknown fields, and must be a mode-`0600` effective-user-owned
regular file in a mode-`0700` directory. `guardian` owns an owner-only AF_UNIX
submission socket and drives `GuardianP2p` plus the existing authenticated
collector boundary; `relay` drives only the bounded relay service.

Local submission frames are exact and versioned: protocol byte, canonical
transport PeerId length and UTF-8 bytes, ballot length, and the unchanged ballot
bytes. Request and response EOF are mandatory. Results are limited to accepted,
duplicate, rejected, busy, or transport failure. JSON lifecycle and health
records exclude ballots, collector responses, and local paths. SIGINT/SIGTERM
stops admission/listeners, drains bounded work, and removes the owned socket.
This API adds no Guardian membership, signature, reputation, stake, reward, or
chain authority.

### Guardian Explicit Relay Bootstrap (GH-52)

Relay-role TOML accepts optional `advertise_addresses` separately from
`listen_addresses`. Every entry must be one canonical non-wildcard,
non-multicast IP/UDP/QUIC-v1 address with a non-zero port. DNS/mDNS, malformed,
duplicate, oversized, over-limit, and noncanonical values fail closed.

Preflight schema version 2 reports only the advertised-address count. Runtime
operator records also use schema version 2 and emit one `bootstrap-route` JSON
record per configured address, appending the persistent transport `PeerId`.
The route is registered as a libp2p external address but remains untrusted
operator metadata: it is not reachability proof, Guardian membership, key
assignment, or chain authority.

### Light Client ThreatHint Transport Core (GH-55)

The shared `prometheus-threat-hint` crate defines canonical schema v1 with
integer confidence basis points, exact lowercase hashes/nonces, explicit proof
system, bounded proof bytes, and a non-zero observation timestamp. Unknown or
duplicate fields, noncanonical JSON, trailing data, malformed values, and
envelopes over 2048 bytes fail closed.

`GuardianP2p::send_threat_hint()` uses the independent
`/prometheus/threat-hint/1.0.0` request-response behavior. Ballot and ThreatHint
request maps and response channels are separate, while their total admitted
inbound/outbound work shares the configured global cap. The raw API exposes
`InboundThreatHint` and requires an explicit `respond_threat_hint()` decision.

The Light Client `ThreatHintBuilder` binds proof public input to the exact
threat hash, floors finite confidence into basis points, and refuses
`development_stub_v1` in beta/mainnet modes. It does not verify opaque Groth16
bytes.

### Guardian ThreatHint Verifier Ingress (GH-58)

`UnixThreatHintIngress` forwards exact canonical bytes over a distinct
owner-only AF_UNIX socket. Its canonical response is
`{payload_digest,protocol_version,status}`; non-`busy` responses bind the
SHA-256 digest of the exact request, while `busy` is deliberately unbound.
Socket ownership/mode, peer UID, frame bounds, timeout, EOF, schema, and
canonical ACK encoding are all checked independently of ballot ingress.

Python `ThreatHintIngress` re-parses schema v1, rejects development stubs,
checks freshness and monotonic time, and invokes an injected verifier with the
exact canonical bytes plus trusted local `network_id` and domain separation.
An accepted result atomically commits nonce/hash/digest replay identities and
one durable `VerifiedThreatHintJob` in SQLite. `pending_jobs(limit)` is
bounded to 256 and never invents concrete analyzer indicators absent from the
wire schema. The default verifier is unavailable and returns fail-closed
`busy`; no production `accepted` claim exists until an independently
approved Groth16 relation, verifying key, and vectors are injected. `PeerId`
remains routing metadata only.

### Guardian ThreatHint Analyzer Adapter (GH-74)

`ThreatHintAnalyzerAdapter` consumes at most 32 pending jobs per call. It
re-parses canonical bytes, verifies the stored digest, exact trusted network,
real proof mode, and original admission window, then constructs a frozen
`VerifiedThreatHint` containing only v1 wire/job fields. The verified type has
no concrete indicator list. `Analyzer.process_verified_threat_hint()` therefore
does not invoke the LLM or YARA generator and returns only a hash-bound result
with confidence `0.0`, no rule, and `should_submit = false`.

Drain calls are serialized per adapter instance. `drain_once()` returns an
structurally immutable `ThreatHintDrainReport` with tuples of delivered results and
`ThreatHintDrainFailure` records. Each failure exposes only its bounded batch
index, fixed `adapt|analysis|clock|delivery` category, and a validated lowercase
32-byte digest or `None`; canonical bytes, paths, analyzer output, and arbitrary
exception text are excluded. A failed job remains pending while later safe jobs
in the same batch continue. Cancellation and other `BaseException` conditions
still abort. A job is marked delivered only after the exact safe result passes
adapter validation and the delivery clock is valid. This is a non-actionable v1
consumption path, not accepted rule generation. A future observable-bearing
schema/channel and any side-effecting multi-process consumer require separate
review.

### Local Threat Observable bundle APIs (GH-82/GH-86/GH-90/GH-94/GH-103/GH-107)

`docs/threat-observable-v2.md` remains the normative design draft for the
future protocol. Merged and exact-main-verified GH-86 implements only its local canonical bundle boundary:

```text
Rust: prometheus_threat_hint::ObservableBundle
  parse_canonical(&[u8])
  to_canonical_bytes()
  commitment(network_id, report_nonce_hex)
  commitment_matches(expected, network_id, report_nonce_hex, wire)

Rust GH-90 merged/exact-main:
  produce_file_sha256_bundle(&[u8], ScopePlatform, ScopeFormat)

Rust GH-94 merged/exact-main (validated with separate producer vectors):
  produce_byte_pattern_bundle(
    &[u8], usize, &[bool], ScopePlatform, ScopeFormat
  )

Rust GH-103 local Linux ELF producer:
  produce_elf_api_import_bundle(&[u8], usize)

Rust GH-107 local approval verifier:
  ObservableApprovalContext::new(
    &[u8; 32], &[u8; 32], &[u8; 32], &str, u64
  )
  verify_observable_approval(&[u8], &[u8], &ObservableApprovalContext)

Python: jaeger.threat_observable.ObservableBundle
  parse_canonical(bytes)
  canonical_bytes
  commitment(network_id, report_nonce_hex)
  commitment_matches(expected, network_id, report_nonce_hex, wire)

Python GH-107 local approval verifier:
  jaeger.observable_approval.ObservableApprovalContext
  jaeger.observable_approval.verify_observable_approval(bytes, bytes, context)
```

The Rust/Python bundle validators consume the shared
`modules/threat-hint/tests/vectors/threat-observable-bundle-v1.json` corpus.
GH-94 producer validation separately consumes
`modules/threat-hint/tests/vectors/threat-observable-byte-pattern-producer-v1.json`.
GH-103 producer validation consumes
`modules/threat-hint/tests/vectors/threat-observable-elf-api-import-producer-v1.json`;
Python independently parses that exact ELF64 dynamic-symbol fixture before
validating the canonical bundle bytes.
GH-107 consumes the public-only
`modules/threat-hint/tests/vectors/threat-observable-approval-v1.json` vector;
Rust and Python independently recompute the bundle commitment, signing digest,
BIP340 verification result, and deterministic approval ID.
Rust public bundle types cannot be deserialized directly, and Python direct
constructors are disabled; commitment calculation is reachable through a
validated parsed bundle. Value-bearing Rust `Debug` and Python `repr` output is
disabled. A new ThreatHint v2 wire, proof statement/relation, owner-only
pairing, analyzer promotion, and network protocol require separate review and
remain unavailable.

The local validator checks canonical structure, exact kind/value grammar,
ordering, bounds, and commitment context only. It does not prove that an
`api_import` value came from a reviewed binary-import extractor or that a
grammar-valid value is semantically safe to disclose. The producer must use
separately reviewed kind-specific extractors; no arbitrary-string builder is an
approved disclosure API.

The GH-90 function is the first such kind-specific producer. It computes one
lowercase SHA-256 internally from exact caller-supplied bytes, always emits the
structural `public_auto_v1` profile, and accepts no path, digest string, or
generic observable value. That profile does not authorize disclosure or
transport. Python remains an independent validator consumer rather than
gaining an unused producer API.

The merged GH-94 producer selects a checked 8..=64-byte range from exact
caller-supplied bytes. A same-length boolean mask emits `??` for wildcard
positions and lowercase hex for fixed positions; at least eight positions must
remain fixed. It accepts no pattern string, always emits exactly one
`review_required_v1` observable, and enables no transport. Python independently
derives and validates the shared vector outputs without gaining a producer API.

The GH-103 producer accepts exact artifact bytes plus a checked import index
only. It parses Linux ELF dynamic symbols through exactly pinned `object
0.39.1` read-only features, rejects empty/non-ELF/malformed/oversized input,
rejects any import outside the closed grammar, bounds input to 16 MiB and 4096
dynamic symbols, sorts and deduplicates by exact ASCII bytes, and derives
`linux`/`elf` scope internally. Every result is `review_required_v1`. It
accepts no path, import string, caller-supplied scope, or generic value and
performs no transport, proof, analyzer, wallet, signing, or chain operation.

Merged and exact-main-verified GH-107 verifies one exact canonical approval envelope for one
exact `review_required_v1` bundle. The trusted context supplies the report
nonce, exact x-only approver key, recipient-scope digest, network, and a
separately trusted current time that must never be attacker-controlled. Both
implementations enforce a 1024-byte wire cap, exact field order and
lowercase hex, fixed purpose `guardian_analysis_v1`, inclusive validity of at
most 3600 seconds, commitment recomputation, and the domain-separated BIP340
signature. The API contains no signing/private-key path and performs no
transport, persistence, promotion, disclosure, analysis, proof, wallet, or
chain action. `approval_id` and `approval_nonce` identify repeated submissions
but do not prevent replay; future consumption requires a durable one-time-use
store and separately reviewed authority/recipient policy.

---

## 4. SILVERSCRIPT CONTRACT API

### ValidatorStaking

```silverscript
// Öffentliche Funktionen
function register(pubkey: bytes(32)) -> void
function commitVote(proposal_id: uint64, commitment: bytes(32), bond_kas: uint64) -> void
function revealVote(proposal_id: uint64, vote: bool, salt: uint64) -> void
function unstake() -> void  // nach COOLDOWN_BLOCKS

// Lesende Funktionen
function getValidator(addr: address) -> Validator
function getStake(addr: address) -> uint64
function isActive(addr: address) -> bool
```

### GuardianReputation

```silverscript
function register(pubkey: bytes(32), compute_power_gflops: uint64) -> void
function submitContribution(threat_hash: bytes(32), rule_ipfs: bytes(46), confidence: uint64) -> uint64
function votingPower(addr: address) -> uint64  // reputation^2 * compute / 1000

// Nur intern (durch Governance aufgerufen)
function proposalAccepted(guardian_addr: address) -> void
function proposalRejected(guardian_addr: address) -> void
```

### DevIncentivePool

```silverscript
function proposeGrant(developer: address, contribution_hash: string,
                      description: string, lines: uint64,
                      complexity: uint64, amount: uint64) -> uint64  // grant_id
function vote(grant_id: uint64, support: bool) -> void
function recommendedReward(lines: uint64, complexity: uint64) -> uint64
```

---

## 5. KOMMUNIKATIONS-PROTOKOLL (P2P)

### Implemented Guardian transport protocols

```text
/prometheus/guardian-ballot/1.0.0
  request: 2-byte big-endian length + 1..=8192 opaque canonical ballot bytes
  response: accepted | duplicate | rejected | busy

/prometheus/threat-hint/1.0.0
  request: 2-byte big-endian length + 1..=2048 canonical schema-v1 JSON bytes
  response: accepted | duplicate | rejected | busy
```

Both require exact EOF. QUIC-v1 direct and relay-circuit routes are implemented.
No TCP port, generic PROM header, handshake-based identity, or transport ZK
authentication is implemented. `PeerId` never grants application authority.

### Still open

```text
1. Independently approved production Groth16 relation, keys, and vectors
2. Reviewed observable extractors, provenance/privacy gates, and v2 wire/pairing
3. Broad discovery and trusted Guardian membership/key assignment
4. Light Client rule-update subscription
```

---

## 6. FEHLER-CODES

```rust
pub enum PrometheusError {
    // Blockchain
    RpcConnectionFailed(String),
    TransactionFailed(String),
    RuleNotFound(String),
    
    // KI
    ModelNotLoaded,
    InferenceFailed(String),
    ZkProofGenerationFailed(String),
    
    // Netzwerk
    PeerConnectionFailed(String),
    MessageDecodeFailed(String),
    
    // Contracts
    InsufficientStake { required: u64, actual: u64 },
    InsufficientReputation { required: f64, actual: f64 },
    VotingPeriodExpired,
    AlreadyVoted,
    
    // Allgemein
    InvalidSignature,
    Unauthorized,
    NotFound(String),
}
```
