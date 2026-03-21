# PROMETHEUS – API DEFINITIONEN
# Stabile Schnittstellen-Definitionen für alle Module.
# Änderungen hier erfordern einen Audit durch Claude.
# Last Updated: 2026-03-21

---

## 1. KASPA RPC API (rusty-kaspa)

### Verbindung

```rust
// Testnet
const TESTNET_RPC: &str = "ws://127.0.0.1:16210";
const MAINNET_RPC: &str = "ws://127.0.0.1:16110";

// Verbindung aufbauen
let client = RpcClient::connect(rpc_url, NetworkId::Testnet12).await?;
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
