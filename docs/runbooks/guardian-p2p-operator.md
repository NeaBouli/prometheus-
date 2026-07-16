# Guardian P2P Operator Runbook (GH-44)

## Purpose

Document the currently implemented GH-44 transport candidate for operated Guardian-sidecar communication: persisted transport identity, bounded routes, operated relay/NAT instrumentation, and race-tested admission behavior.

## Scope of this implementation

- Transport identity is persisted locally and reused.
- `PeerId` is metadata only, never a Guardian trust decision.
- Transport remains opaque ballot request/ACK exchange (`/prometheus/guardian-ballot/1.0.0`) with a Python collector behind an owner-only Unix socket.
- No wallet, chain, signature, reputation, tokenomics, or committee-auth assignment.

## Startup and config

1) Prepare identity directory and path

```bash
mkdir -p /var/lib/prometheus/guardian-p2p
chmod 700 /var/lib/prometheus/guardian-p2p
```

- Use an **absolute** path for transport identity.
- The directory must be mode `0700`. A generated identity is mode `0600`; an existing identity may be owner-read-only, but must have no execute, group, or world bits.

2) Build runtime config (`GuardianP2pConfig` in crate use site)

- Listener routes: direct IP/UDP/QUIC-v1 or exact relay reservations ending in `/p2p-circuit`.
- Static routes: direct QUIC-v1 or exact relay-circuit with `p2p-circuit`.
- AutoNAT routes: exact direct QUIC-v1 routes only.
- No DNS routes (DNS-based routes are rejected).
- Keep route count and timeout values bounded.

3) Start relay node for operated relay path (when used)

- Relay service requires direct QUIC-v1 listener address.
- Relay limits are bounded in config and hard-coded relay caps (reservations/circuits/time windows).
- Observe relay events:
  - `ReservationAccepted`
  - `CircuitAccepted`
  - `CircuitClosed`
  - relay and direct transport events from participants.

4) Start sidecar nodes

- Use `GuardianP2p::new` with:
  - static peer entries for direct peer and relay circuit routes
  - an explicit direct AutoNAT server route when reachability classification is required
  - local Unix ingress validated with owner-only permissions and bounded size/timeout.
- Run event loop calling `next_sidecar_event` to process inbound ballots and send bounded collector outcomes.

## Operated relay evidence (deterministic harness)

`relay_service.rs` test `operated_relay_delivers_ballot_and_preserves_fallback` provides the current deterministic, isolated three-node proof:

- Nodes: one relay service, one receiver, one sender.
- Steps observed:
  - relay reservation on receiver route,
  - relayed inbound ballot delivery,
  - relayed ACK back to sender,
  - AutoNAT reports public path on sender,
  - DCUtR outcome is relay fallback,
  - circuit and relayed connection close events are observed after receiver stop.

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
cargo test -p prometheus-guardian-p2p configuration_accepts_exact_direct_and_relay_routes
cargo test -p prometheus-guardian-p2p configuration_rejects_dns_mismatches_duplicates_and_unbounded_routes
cargo test -p prometheus-guardian-p2p closed_response_channel_race_is_nonfatal
cargo test -p prometheus-guardian-p2p canceled_peer_keeps_capacity_until_ingress_finishes
cargo test -p prometheus-guardian-p2p
cargo fmt --all -- --check
cargo clippy -p prometheus-guardian-p2p --all-targets -- -D warnings
cargo audit
```

## Explicit exclusions

- Do not treat this crate as discovery, membership, signing, chain governance, or token-distribution logic.
- Do not claim public relay operation, mDNS discovery, or multi-host production packaging as complete.
