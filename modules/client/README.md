# Prometheus Light Client

This crate contains an implemented and tested **development foundation**, not
a production malware detector or reporting client.

## Current Boundary

- `ai/phi3.rs` checks for a configured model path but runs a deterministic
  entropy heuristic. It creates no ONNX Runtime session and performs no model
  inference.
- `security/scanner.rs` is a custom YARA-style pattern matcher. It is not
  evidence of production YARA malware detection or real-sample quality.
- `blockchain/krc20.rs` observes the Kaspa DAG and returns a development cache;
  canonical Kaspa state/CID and IPFS content loading are not implemented.
- `blockchain/rule_state.rs` strictly decodes exact caller-supplied current-
  Silverc `RuleStorageState` constructor JSON into normalized accepted-rule
  metadata. It is development-only and proves neither chain provenance nor
  finality.
- `blockchain/rule_observation.rs` checks one separately SHA-256-pinned,
  canonical Testnet-10 manifest against a bounded caller-supplied RPC-shaped
  UTXO set before invoking the state decoder. It requires one unique outpoint
  match plus exact covenant, script, amount, block-DAA, and maturity-proxy
  agreement. It proves manifest-to-observation consistency only, not manifest
  authority, RPC truth, transaction history, finality, or a live chain read.
- `blockchain/rule_fetch.rs` provides a credential-free, loopback-IP-literal-
  only HTTP source for one local IPFS gateway. It disables redirects and
  proxies, bounds waits and content to 64 KiB, and returns exact bytes only
  after canonical Raw-CIDv1 validation. This is local development acquisition,
  not IPFS availability, replication, or censorship-resistance evidence.
- `blockchain/rule_sync.rs` composes the injected/live Testnet-10 observation,
  constructor-state decoding, restricted content fetch, exact CID binding, and
  one atomic complete-snapshot scanner replacement. It has no automatic update
  loop or product-runtime wiring and grants no manifest, RPC, finality, YARA,
  rollback, or production authority.
- `blockchain/rule_checkpoint.rs` adds a development-only owner-local POSIX
  checkpoint around that sync. It digest-binds exact verified identities, uses
  the minimum verified observation virtual DAA as the conservative snapshot
  order, rejects rollback and same-order equivocation, and restores scanner
  state through exact replay after restart. It adds no canonical authority,
  availability proof, production YARA, or production wiring.
- `blockchain/rule_coordinator.rs` adds an explicit opt-in development lifecycle
  around that durable transaction: one immediate attempt, a fixed interval after
  success, sequential retries with capped exponential failure backoff, bounded
  timeout, cancellation with no detached
  work, single-flight admission, and bounded non-sensitive status counters. It
  accepts a caller-trusted complete-snapshot provider and by itself adds no
  product runtime, autonomous authority, RPC/finality proof, availability proof, wallet,
  chain action, Mainnet support, or production readiness.
- `blockchain/rule_signed_snapshot.rs` adds a strict canonical
  development/Testnet-10 complete-snapshot envelope authenticated with BIP340
  against a separately owner-pinned x-only key. It binds sequence, a maximum
  one-hour validity window, entries, and explicit empty-snapshot order; an
  external nonzero minimum sequence and separately trusted clock are enforced,
  with the clock rechecked on every fetch. It includes no signer/private-key
  path, key-authority or rotation proof, persistent sequence authority,
  canonical L1/RPC/finality proof, availability proof,
  wallet/chain action, deployment, Mainnet support, or production readiness.
- `rule_sync_cli.rs` and the `rule-sync preflight/run` command are the GH-213
  repository candidate for an operator-invoked composition of those existing
  boundaries. They require private, no-symlink, bounded config and envelope
  files, restrict the config to ASCII TOML,
  accept only loopback-IP-literal RPC/IPFS endpoints, keep preflight offline and
  checkpoint-free, emit redacted counters, and cancel without detached work.
  This remains Development/Testnet-10 only and establishes no key authority,
  persistent sequence authority, autonomous distribution, chain write,
  availability, deployment, Mainnet, or production readiness.
- `blockchain/rule_ingest.rs` ingests a complete caller-supplied active-rule
  snapshot whose raw CIDv1 (sha2-256, canonical lowercase base32) must bind the
  exact caller-supplied content bytes. It parses a strict simple matcher
  grammar — not real YARA syntax — and replaces scanner rules atomically
  (an empty snapshot clears them). It is development-only: beta, mainnet, and
  production profiles reject it. Canonical autonomous Kaspa/IPFS rule loading,
  production YARA, and canonical rule authority remain open.
- `network/zk_proof.rs` produces a development SHA-256 placeholder, not a
  production zero-knowledge proof.
- The E2E lifecycle test is an in-process, same-host stub fixture. Its
  under-60-second assertion is a target guard, not public-network performance
  evidence.

Beta, mainnet, and production runtime profiles reject these stubs. Production
use remains blocked on real Phi-3/ONNX inference and real-sample evaluation,
approved proof artifacts, canonical rule loading, reviewed P2P reporting,
privacy controls, and multi-host evidence.
