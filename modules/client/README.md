# Prometheus Light Client

This crate contains an implemented and tested **development foundation**, not
a production malware detector or reporting client.

## Current Boundary

- `ai/phi3.rs` is a fail-closed development stub. It never reports a loaded
  model from path existence, creates no ONNX Runtime session, performs no
  model inference, and in Development returns a safe default for inputs up to
  16 MiB (not suspicious, confidence 0.0, no quarantine authority) instead of
  heuristic verdicts. Beta/Mainnet profiles and oversized inputs fail closed.
- `security/scanner.rs` is a custom YARA-style pattern matcher. It is not
  evidence of production YARA malware detection or real-sample quality.
- `security/heuristic.rs` performs bounded, deterministic integer scoring over
  exact caller-supplied bytes and reports only structural triage reasons. It
  does not monitor APIs, processes, paths or the operating system, does not
  label content malicious, and cannot authorize quarantine.
- `security/quarantine.rs` is an owner-local, digest-verified exact-byte vault.
  It never receives a source path, moves or deletes source files, prevents
  execution, or performs automatic isolation.
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
- Merged and exact-main-verified GH-213/PR #214 at `bbe7efb` adds
  `rule_sync_cli.rs` and the `rule-sync preflight/run` command as an
  operator-invoked composition of those existing boundaries. They require
  private, no-symlink, bounded config and envelope
  files, restrict the config to ASCII TOML,
  accept only loopback-IP-literal RPC/IPFS endpoints, keep preflight offline and
  checkpoint-free, emit redacted counters, and cancel without detached work.
  This remains Development/Testnet-10 only and establishes no key authority,
  persistent sequence authority, autonomous distribution, chain write,
  availability, deployment, Mainnet, or production readiness.
- Merged and exact-main-verified GH-216/PR #217 at `13c1812` adds a test-only
  real-`prometheus-client` binary harness over ephemeral loopback wRPC/IPFS
  peers. It covers offline/connected preflight, private checkpoint commit,
  SIGTERM/SIGINT drain, restart exact replay, rollback/equivocation rejection,
  and malformed, timeout, or disconnected peer paths; CI `31978132036`,
  Security `31978132044`, and Pages `31978131647` pass. This remains local
  Development evidence, not public Testnet operation, independent RPC/IPFS
  truth or availability, deployment, Mainnet, or production readiness.
- GH-226 adds `network/p2p.rs` and `threat-hint preflight|submit` as one
  Development-only, dial-only v1 sender composed from the existing Guardian
  P2P stack. It accepts one canonical static literal-loopback QUIC peer, strict
  owner-only config/hint/identity paths, exact canonical bytes and a 1–60
  second bound. Real same-host binary/QUIC tests cover
  accepted/duplicate/rejected/busy/transport-failure with redacted output.
  Beta and Mainnet reject before dialing. This grants no proof, membership,
  discovery, public/multi-host, wallet, chain, reward, deployment or production
  authority. PR #227 merged as exact main `6c39af5`; Prometheus CI
  `32675287618`, Security Audit `32675287530`, and Pages `32675287300` pass.
- Merged GH-229/PR #230 at exact main `fba8bb4` preserves that loopback default
  and adds one explicit `controlled-remote-testnet10` route for a single
  canonical direct literal-IP/UDP/QUIC-v1 peer. Unsafe/special ranges, mapped
  IPv6, DNS, TCP, relay and peer mismatches fail closed. At
  `2026-08-26T23:36:04Z` (2026-08-27 operator-local), one operator-attested run
  from source commit `27e8b02` delivered one canonical hint between two
  distinct controlled hosts with `rejected`/`rejected`, zero
  retries, no persistence and acknowledgement authority `none`; the temporary
  sender-restricted UDP rule was removed immediately. The
  [redacted evidence](../../docs/evidence/gh-229-controlled-two-host-2026-08-27.json)
  does not independently prove separation and is not public reporting,
  relay/v2, deployment or production evidence. Exact-main CI `33017195813`,
  Security Audit `33017196184`, and Pages `33017194744` pass for the merged
  capability.
- Merged and exact-main-verified GH-234/PR #235 (code `b450740`, exact main
  `f146fb2`; CI `33272578070`, Security `33272577951`, Pages `33272577407`) adds
  the separate `threat-hint-v2 preflight|submit --config
  <owner-only TOML> --payload <owner-only canonical binary>` command as one
  Development-only, dial-only sender for an owner-prepared canonical
  ThreatHint-v2 transport payload (proof envelope, Observable Bundle, approval,
  and report nonce in the shared `ThreatHintV2TransportPayload` framing). It
  reuses the GH-226/GH-229 route, identity, timeout, and one-static-peer policy
  unchanged. The payload is read from an owner-only, no-symlink, size-bounded
  file and parsed exclusively with
  `prometheus_threat_hint::ThreatHintV2TransportPayload::parse_canonical`
  against the separately trusted `testnet-10` network — with an exact canonical
  re-emission check — before any identity load or network activity. On submit
  the client pins `threat_hint_v2_trusted_network_id` to `testnet-10`, sends
  exactly once over `/prometheus/threat-hint/2.0.0`, drives only the matching
  request-id events, and reports a data-minimal
  accepted/rejected/busy/transport-failure status. There is no retry,
  persistence, discovery, or listener. The client never generates, signs, or
  verifies proof or approval authority, and the acknowledgement is never proof,
  approval, membership, reward, or chain authority. Beta and Mainnet reject
  before identity or network activity; loopback remains the default and the
  GH-229 `controlled-remote-testnet10` opt-in applies unchanged. Real
  same-host binary/QUIC tests cover accepted/rejected/busy/transport-failure
  with exact bytes, one attempt, and redacted output. This grants no public or
  multi-host operation, wallet, chain, deployment, or production authority.
- Merged and exact-main-verified GH-238/PR #239, exact main `912d96d`,
  implements and locally tests repository-only preparation for one
  later controlled distinct-host
  Development/Testnet-10 ThreatHint-v2 attempt. The tooling uses
  challenge-bound, role-specific operator attestations over the source commit,
  the actual executable digest, the exact canonical payload digest, the exact
  v2 protocol, one shared observed UTC time, the actual rejected status, one
  attempt, zero retries and no persistence, with strict owner-only/no-symlink
  files, the exact 9,265-byte Rust wire bound, atomic no-clobber record output,
  a closed redacted verifier and CI test wiring. Exact-main CI `33279351831`,
  Security Audit `33279351822`, and Pages `33279351387` pass.
  No real GH-238 remote run has occurred and no GH-238 evidence record exists;
  host separation is not independently proven. This repository preparation is
  not a deployment or remote demonstration and adds no port, firewall, host,
  IAM, wallet, chain, deployment, Mainnet or production action or authority; a
  later real run requires separate explicit authorization.
- `blockchain/rule_ingest.rs` ingests a complete caller-supplied active-rule
  snapshot whose raw CIDv1 (sha2-256, canonical lowercase base32) must bind the
  exact caller-supplied content bytes. It parses a strict simple matcher
  grammar — not real YARA syntax — and replaces scanner rules atomically
  (an empty snapshot clears them). It is development-only: beta, mainnet, and
  production profiles reject it. Canonical autonomous Kaspa/IPFS rule loading,
  production YARA, and canonical rule authority remain open.
- `network/zk_proof.rs` produces a development SHA-256 placeholder, not a
  production zero-knowledge proof.
- The original E2E lifecycle test is an in-process, same-host stub fixture. Its
  under-60-second assertion is a target guard, not public-network performance
  evidence. The GH-216 real-binary harness also remains same-host and loopback;
  neither fixture proves public-network performance or operation.

Beta, mainnet, and production runtime profiles reject these stubs. Production
use remains blocked on real Phi-3/ONNX inference and real-sample evaluation,
approved proof artifacts, canonical rule loading, operated public/multi-host P2P reporting,
privacy controls, and multi-host evidence.
