# Prometheus Guardian P2P

## GH-44 implementation (as implemented)

This workspace crate is the transport-only Guardian ballot carrier. GH-44 adds persisted transport identity and operated relay/NAT evidence while keeping no Guardian identity/auth role inside transport.

- `PeerId` remains transport metadata only. It is never a Guardian identity, membership value, signing key, chain account, reputation index, or tokenomics key.
- Persistent Ed25519 transport identity via `load_or_create_transport_identity`.
- Identity path must be absolute; parent must be owner-only directory mode `0700`.
- Generated identity files use mode `0600`; an existing regular file may be `0400` or `0600`, but must be owner-readable with no execute, group, or world bits.
- Parent and file opens use `NOFOLLOW` to reject symlink path escape.
- Identity is loaded from a bounded protobuf payload (`<= 1024` bytes) and validated as canonical encoding.
- Identity creation is atomic and same-directory: write encoded key to a unique temporary file with mode `0600`, then hard-link publish.
- Concurrent creators are safe; one winning key is reused and no `*.tmp-*` artifacts are left behind.

- Transport routes are strictly bounded:
  - listener addresses must be IP/UDP/QUIC-v1 or direct relay reservation routes and bounded `<= 512` bytes
  - static peers must be direct QUIC-v1 or exact relay-circuit route
  - AutoNAT servers must be exact direct QUIC-v1 peer route
  - listeners and peers may not use DNS/mDNS, and no DNS-based route is accepted.
- QUIC-v1 relay service listener policy is strictly direct; no relay-listener-within-relay.
- Operated relay harness and telemetry are in crate tests via `operated_relay_delivers_ballot_and_preserves_fallback`:
  - three deterministic nodes (`relay`, `receiver`, `sender`)
  - reservation established from receiver to relay
  - relayed ballot delivery and ACK
  - AutoNAT classification as `Public` for direct sender path in harness
  - DCUtR attempted and observed as relay fallback
  - circuit close and relayed disconnect are observed.
- Data-minimal operational events from relay/transport are available through enums and include only transport metadata (`peer`, `path`, `peer count`, `status`, `request ids`).
- Inbound ingress and local collector path is owner-only `UnixBallotIngress` with bounded reads/writes, and bounded ack behavior.
- Concurrency and race hardening is covered by transport tests for:
  - canceled peer keeps capacity until ingress completes
  - closed response channel race is nonfatal
  - sidecar throughput remains safe under out-of-order ingress completions
  - concurrent creation for persisted identity.

## Boundary

- QUIC direct and relay paths; protocol `/prometheus/guardian-ballot/1.0.0`.
- Ballots are opaque byte frames bounded to `8192` bytes.
- One-byte responses: `accepted`, `duplicate`, `rejected`, or `busy`.
- Request-response and connection limits are bounded, with one outbound stream per connection default.
- Local collector I/O failures map to bounded `busy`/`rejected` outcomes.

The transport cannot do or claim:

- Guardian enrollment, membership, trusted authentication, or chain governance.
- Wallet keys, signature validation, or transaction flow.
- Reputation/SLASH score handling.
- tokenomics logic.
- public relay bootstrap, multi-host operated package, or mDNS-based discovery.
- autonomous relay-server package shipping.

## Verification

```bash
cargo test -p prometheus-guardian-p2p
cargo fmt --all -- --check
cargo clippy -p prometheus-guardian-p2p --all-targets -- -D warnings
cargo audit
```

Key tests to run first:

```bash
cargo test -p prometheus-guardian-p2p concurrent_creation_returns_one_peer_id
cargo test -p prometheus-guardian-p2p operated_relay_delivers_ballot_and_preserves_fallback
cargo test -p prometheus-guardian-p2p configuration_accepts_exact_direct_and_relay_routes
cargo test -p prometheus-guardian-p2p configuration_rejects_dns_mismatches_duplicates_and_unbounded_routes
cargo test -p prometheus-guardian-p2p closed_response_channel_race_is_nonfatal
cargo test -p prometheus-guardian-p2p canceled_peer_keeps_capacity_until_ingress_finishes
```

## Not yet proven by GH-44

- Broad peer discovery and public relay bootstrap.
- Multi-host packaged operator operation.
- Public service hardening for multi-instance deployment.
