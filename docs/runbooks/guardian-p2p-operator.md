# Guardian P2P Operator Runbook (GH-48 + GH-52)

## Purpose

Operate the merged GH-48 Guardian sidecar or relay with persisted transport identity, strict owner-only configuration, bounded local submission, JSON health, and graceful shutdown.

Supported target: Unix-like systems with AF_UNIX peer credentials. Protected CI verifies Linux. Windows and public macOS packaging remain outside the current package.

## Scope of this implementation

- Transport identity is persisted locally and reused.
- `PeerId` is metadata only, never a Guardian trust decision.
- Transport remains opaque ballot request/ACK exchange (`/prometheus/guardian-ballot/1.0.0`) with a Python collector behind an owner-only Unix socket.
- No wallet, chain, signature, reputation, tokenomics, or committee-auth assignment.
- `PeerId` and all emitted addresses are transport metadata only.

## Startup and config

1) Prepare identity directory and path

```bash
mkdir -p /var/lib/prometheus/guardian-p2p
chmod 700 /var/lib/prometheus/guardian-p2p
```

- Use an **absolute** path for transport identity.
- The directory must be mode `0700`. A generated identity is mode `0600`; an existing identity may be owner-read-only, but must have no execute, group, or world bits.

2) Prepare the service and socket directory

```bash
mkdir -p /var/lib/prometheus/guardian-p2p /run/prometheus/guardian-p2p
chmod 700 /var/lib/prometheus/guardian-p2p /run/prometheus/guardian-p2p
```

- The collector and ThreatHint verifier must create their independent Unix sockets with mode `0600` in the owner-only runtime directory.
- The sidecar creates its submission socket with mode `0600` and removes it after graceful shutdown.
- Identity, collector, ThreatHint, and submission paths must be distinct absolute file paths.

3) Write an owner-only Guardian config

```toml
role = "guardian"
identity_path = "/var/lib/prometheus/guardian-p2p/identity"
collector_socket = "/run/prometheus/guardian-p2p/collector.sock"
threat_hint_socket = "/run/prometheus/guardian-p2p/threat-hint.sock"
submission_socket = "/run/prometheus/guardian-p2p/submit.sock"
listen_addresses = ["/ip4/0.0.0.0/udp/4101/quic-v1"]
health_interval_secs = 30
ingress_timeout_secs = 10
collector_startup_timeout_secs = 30
shutdown_drain_timeout_secs = 10
max_local_submissions = 32
static_peers = []
autonat_servers = []
```

```bash
chmod 600 /var/lib/prometheus/guardian-p2p/service.toml
prometheus-guardian-p2p preflight --config /var/lib/prometheus/guardian-p2p/service.toml
```

Preflight is network-free, rejects unknown/unbounded fields, and emits a path-free JSON report. It creates or securely reuses the persistent transport identity.

4) Configure routes

- Listener routes: direct IP/UDP/QUIC-v1 or exact relay reservations ending in `/p2p-circuit`.
- Static routes: direct QUIC-v1 or exact relay-circuit with `p2p-circuit`.
- AutoNAT routes: exact direct QUIC-v1 routes only.
- No DNS routes (DNS-based routes are rejected).
- Keep route count and timeout values bounded.

5) Start a relay role when used

```toml
role = "relay"
identity_path = "/var/lib/prometheus/guardian-p2p/relay.identity"
listen_addresses = ["/ip4/0.0.0.0/udp/4100/quic-v1"]
advertise_addresses = ["/ip4/203.0.113.10/udp/4100/quic-v1"]
health_interval_secs = 30
shutdown_drain_timeout_secs = 10
```

- Relay service requires direct QUIC-v1 listener address.
- `advertise_addresses` is optional and relay-only. Replace the documentation address with an operator-controlled routable IP and the externally forwarded UDP port.
- Advertised routes reject DNS/mDNS, wildcard, multicast, port zero, duplicates, noncanonical text, and non-QUIC shapes.
- A `bootstrap-route` event appends the persistent relay transport `PeerId` to each configured advertised address. The event is operator metadata, not a reachability or authorization claim.
- Relay limits are bounded in config and hard-coded relay caps (reservations/circuits/time windows).
- Observe relay events:
  - `ReservationAccepted`
  - `CircuitAccepted`
  - `CircuitClosed`
  - relay and direct transport events from participants.

### Controlled two-host bootstrap procedure

This procedure creates real multi-host evidence only when the relay and Guardian run on distinct hosts. Do not label containers, network namespaces, or multiple processes on one machine as multi-host proof.

1. On the relay host, forward one fixed UDP port such as `4100` and restrict ingress to the approved Guardian host addresses where infrastructure permits.
2. Bind the relay to `/ip4/0.0.0.0/udp/4100/quic-v1` and set `advertise_addresses` to the relay's operator-controlled routable IP and the same external UDP port.
3. Run preflight, then start the relay. Record the exact `bootstrap-route` JSON line. It has this form:

```text
/ip4/<relay-ip>/udp/4100/quic-v1/p2p/<relay-peer-id>
```

4. On the receiver host, configure the relay reservation listener as `<bootstrap-route>/p2p-circuit`.
5. After the receiver emits `relay-reservation-accepted`, construct its sender route as `<bootstrap-route>/p2p-circuit/p2p/<receiver-peer-id>`.
6. Start the sender with that exact static route and submit one already authenticated canonical ballot through its owner-only local submission socket.
7. Capture path-free evidence for the relay `reservation-accepted` and `circuit-accepted`, receiver `inbound-processed`, sender `outbound-ack`, and clean `stopped` records. Record host identities outside these service logs; the service deliberately does not emit hostnames or local paths.
8. Stop all processes and verify owned submission sockets are removed. Keep transport identity files unchanged for repeatability.

Passing this procedure proves controlled reachability and exact opaque ballot/ACK transport between the tested hosts. It does not prove broad discovery, Guardian membership, Sybil resistance, public-service hardening, or production readiness.

6) Start processes

```bash
prometheus-guardian-p2p run --config /var/lib/prometheus/guardian-p2p/service.toml
```

- Start the existing authenticated collector before the sidecar, or within `collector_startup_timeout_secs`.
- Treat `ready: true` as listener readiness only, not Guardian authorization or public reachability.
- Monitor JSON-line `health`, listener, connection, reservation, circuit, inbound, outbound, and terminal events.
- Drain stdout continuously. JSON-line output uses a bounded dedicated writer; output backpressure or writer failure makes the service fail closed instead of blocking signal handling indefinitely.
- A collector outage returns `busy`; unsafe IPC ownership, framing, or ACK data fails closed.
- A missing, unavailable, or verifier-disabled ThreatHint boundary returns `busy`.
  Invalid canonical data, development proof stubs, stale/replayed conflicting
  data, and invalid proof results return `rejected`. `accepted` means the
  approved proof passed and replay state plus one durable outbox job committed;
  it does not claim that model analysis completed.

7) Submit one canonical ballot

```bash
prometheus-guardian-p2p submit \
  --socket /run/prometheus/guardian-p2p/submit.sock \
  --peer '<canonical-libp2p-peer-id>' \
  --ballot /run/prometheus/guardian-p2p/ballot.bin
```

The local protocol is owner-credential checked, exact-framed, capped at 8192 ballot bytes, and returns only `accepted`, `duplicate`, `rejected`, `busy`, or `transport-failure`.

8) Stop and recover

- Send SIGTERM or SIGINT. The process closes admission/listeners, drains bounded work, confirms submission-server shutdown and socket cleanup, then emits `stopped`.
- Keep the identity path unchanged across restarts to retain the same transport `PeerId`.
- Never delete or replace an identity merely to fix a connectivity problem; diagnose permissions and routes first.

## Operated evidence

`relay_service.rs` test `operated_relay_delivers_ballot_and_preserves_fallback` provides the current deterministic, isolated three-node proof:

- Nodes: one relay service, one receiver, one sender.
- Steps observed:
  - relay reservation on receiver route,
  - relayed inbound ballot delivery,
  - relayed ACK back to sender,
  - AutoNAT reports public path on sender,
  - DCUtR outcome is relay fallback,
  - circuit and relayed connection close events are observed after receiver stop.

`tests/sidecar_process.rs` adds separate-process evidence on one host:

- relay, receiver, sender, local submit client, and collector boundary run independently;
- exact ballot bytes reach the receiver collector through the relay circuit;
- the canonical collector ACK returns to the submit client;
- SIGTERM exits cleanly, submission sockets disappear, and identities remain stable.

This is packaging and lifecycle evidence, not public Internet or multi-host proof. GH-52 adds the explicit bootstrap route needed to run the controlled two-host procedure; live evidence remains separate.

## Recovery and restart guidance

- Persisted identity is loaded first from configured absolute path.
  - On first run with no identity, identity is created.
  - On later runs, same keypair is reused so transport `PeerId` remains stable if path is unchanged.
- If identity file cannot be opened securely (wrong owner, wrong mode, symlink, malformed payload), startup fails closed.
- Restarting the process with same config path is expected to continue with the same transport identity.
- Recovery playbook:
  1. verify identity path and owner-only directory/file permissions,
  2. restart with unchanged config paths,
  3. if restart fails on identity, inspect parent/file mode and symlink flags,
  4. re-run identity and route validation tests before production routing is resumed.

## Verification commands

```bash
cargo test -p prometheus-guardian-p2p concurrent_creation_returns_one_peer_id
cargo test -p prometheus-guardian-p2p operated_relay_delivers_ballot_and_preserves_fallback
cargo test -p prometheus-guardian-p2p --test sidecar_process
cargo test -p prometheus-guardian-p2p configuration_accepts_exact_direct_and_relay_routes
cargo test -p prometheus-guardian-p2p configuration_rejects_dns_mismatches_duplicates_and_unbounded_routes
cargo test -p prometheus-guardian-p2p closed_response_channel_race_is_nonfatal
cargo test -p prometheus-guardian-p2p canceled_peer_keeps_capacity_until_ingress_finishes
cargo test -p prometheus-guardian-p2p --all-targets
cargo fmt --all -- --check
cargo clippy -p prometheus-guardian-p2p --all-targets -- -D warnings
cargo audit
```

## Explicit exclusions

- Do not treat this crate as discovery, membership, signing, chain governance, or token-distribution logic.
- Do not claim broad public relay operation, mDNS discovery, or multi-host production operation as complete from configuration or same-host tests.
