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

### Blockchain Interface

```rust
pub trait BlockchainClient: Send + Sync {
    async fn connect(&self) -> Result<()>;
    async fn get_latest_rules(&self) -> Result<Vec<KaspaRule>>;
    async fn submit_threat_hint(&self, hint: ThreatReport) -> Result<TxId>;
    async fn get_prom_balance(&self, address: &Address) -> Result<u64>;
    fn is_connected(&self) -> bool;
}
```

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

### HTTP API (intern, nicht öffentlich)

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

### Message Format

```
Header (8 bytes):
  - Magic:    0x50524F4D  ("PROM")
  - Version:  1 byte
  - Type:     1 byte (siehe NetworkMessage enum)
  - Length:   4 bytes (Payload-Länge)

Payload: JSON (UTF-8)
```

### Verbindungsaufbau

```
1. TCP-Verbindung auf Port 16420 (Testnet) / 16420 (Mainnet)
2. Handshake: PeerHandshake-Message senden
3. ZK-Proof für anonyme Authentifizierung
4. Subscription: Bedrohungsmeldungen und Regel-Updates
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
