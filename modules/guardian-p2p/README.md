# Prometheus Guardian P2P

## GH-48 operated service

This workspace crate is the transport-only Guardian ballot carrier. GH-42 and GH-44 provide the bounded carrier, persisted transport identity, and relay/NAT evidence. GH-48 packages those APIs as an operated process while keeping Guardian identity and authorization outside transport.

Supported operated target: Unix-like systems with AF_UNIX peer credentials. Protected CI verifies Linux; public Windows or macOS packaging is not claimed.

- Explicit `prometheus-guardian-p2p` binary with `preflight`, `run`, and `submit` commands.
- Strict role-tagged TOML with unknown-field rejection and owner-only config, identity, collector, and submission paths.
- `guardian` and `relay` roles expose conservative bounded settings rather than arbitrary transport internals.
- The Guardian role waits for its existing authenticated collector, owns a local submission socket, continuously drives libp2p, and correlates local requests with network ACKs.
- JSON-line lifecycle, readiness, connection, transport, ACK, and health records contain no ballot or collector bytes and no local filesystem paths.
- SIGINT/SIGTERM stops local admission and network listeners, drains admitted work to a bounded deadline, emits a terminal record, and removes the owned submission socket.
- Missing or refused collector ingress is temporary `busy`; unsafe ownership, modes, symlinks, framing, or acknowledgements still fail closed.
- Listener readiness is live state and is cleared on expired or closed listeners.
- The separate-process test starts a relay, receiver, sender, local submit client, and owner-only collector boundary; it proves exact-byte relay delivery, canonical ACK, graceful shutdown, socket cleanup, and stable transport identities on one host.

Example owner-only Guardian config:

```toml
role = "guardian"
identity_path = "/var/lib/prometheus/guardian-p2p/identity"
collector_socket = "/run/user/1000/prometheus/collector.sock"
submission_socket = "/run/user/1000/prometheus/submit.sock"
listen_addresses = ["/ip4/127.0.0.1/udp/0/quic-v1"]
health_interval_secs = 30
ingress_timeout_secs = 10
collector_startup_timeout_secs = 30
shutdown_drain_timeout_secs = 10
max_local_submissions = 32
static_peers = []
autonat_servers = []
```

The config file must be mode `0600` in an effective-user-owned mode-`0700` directory. Run a network-free validation before starting:

```bash
prometheus-guardian-p2p preflight --config /var/lib/prometheus/guardian-p2p/service.toml
prometheus-guardian-p2p run --config /var/lib/prometheus/guardian-p2p/service.toml
```

Submit an already authenticated canonical ballot to a configured transport peer:

```bash
prometheus-guardian-p2p submit \
  --socket /run/user/1000/prometheus/submit.sock \
  --peer '<canonical-libp2p-peer-id>' \
  --ballot /run/user/1000/prometheus/ballot.bin
```

The CLI never accepts wallet keys, Guardian signing keys, seeds, or raw transactions.

## GH-44 transport foundation

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
- Newline-delimited operator JSON uses a bounded dedicated writer; saturation, output failure, and output-shutdown timeout fail closed without pinning the async service loop.

The transport cannot do or claim:

- Guardian enrollment, membership, trusted authentication, or chain governance.
- Wallet keys, signature validation, or transaction flow.
- Reputation/SLASH score handling.
- tokenomics logic.
- public relay bootstrap, public or multi-host operating evidence, or mDNS-based discovery.
- trusted membership/key assignment, Sybil resistance, or on-chain attestation.

## Verification

```bash
cargo test -p prometheus-guardian-p2p --all-targets
cargo fmt --all -- --check
cargo clippy -p prometheus-guardian-p2p --all-targets -- -D warnings
cargo audit
```

Key tests to run first:

```bash
cargo test -p prometheus-guardian-p2p concurrent_creation_returns_one_peer_id
cargo test -p prometheus-guardian-p2p operated_relay_delivers_ballot_and_preserves_fallback
cargo test -p prometheus-guardian-p2p --test sidecar_process
cargo test -p prometheus-guardian-p2p configuration_accepts_exact_direct_and_relay_routes
cargo test -p prometheus-guardian-p2p configuration_rejects_dns_mismatches_duplicates_and_unbounded_routes
cargo test -p prometheus-guardian-p2p closed_response_channel_race_is_nonfatal
cargo test -p prometheus-guardian-p2p canceled_peer_keeps_capacity_until_ingress_finishes
```

## Not yet proven by GH-48

- Broad peer discovery and public relay bootstrap.
- Public or multi-host operator operation.
- Public service hardening for multi-instance deployment.
