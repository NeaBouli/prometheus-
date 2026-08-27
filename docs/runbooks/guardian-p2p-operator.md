# Guardian P2P Operator Runbook (GH-48 + GH-52 + GH-229)

## Purpose

Operate the merged GH-48 Guardian sidecar or relay with persisted transport identity, strict owner-only configuration, bounded local submission, JSON health, and graceful shutdown.

Supported target: Unix-like systems with AF_UNIX peer credentials. Protected CI verifies Linux. Windows and public macOS packaging remain outside the current package.

## Scope of this implementation

- Transport identity is persisted locally and reused.
- `PeerId` is metadata only, never a Guardian trust decision.
- Transport carries independent bounded ballot, ThreatHint-v1, and
  ThreatHint-v2 request/ACK protocols. The v2 codec requires an explicit trusted
  network before forwarding exact canonical bytes to its owner-only Unix socket.
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

- The collector and both ThreatHint verifier boundaries must create independent Unix sockets with mode `0600` in the owner-only runtime directory.
- The sidecar creates its submission socket with mode `0600` and removes it after graceful shutdown.
- Identity, collector, ThreatHint-v1, ThreatHint-v2, and submission paths must be distinct absolute file paths.

3) Write an owner-only Guardian config

```toml
role = "guardian"
identity_path = "/var/lib/prometheus/guardian-p2p/identity"
collector_socket = "/run/prometheus/guardian-p2p/collector.sock"
threat_hint_socket = "/run/prometheus/guardian-p2p/threat-hint.sock"
threat_hint_v2_socket = "/run/prometheus/guardian-p2p/threat-hint-v2.sock"
threat_hint_v2_trusted_network_id = "testnet-10"
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

### Controlled Light Client ThreatHint procedure (GH-229)

This separate procedure covers one Development/Testnet-10 Light Client sender
and one directly reachable Guardian host. It is not a relay procedure and does
not authorize a public service.

Operational order is binding: Guardian configuration and readiness first,
sender configuration and preflight second, the single-shot boundary last. The
boundary accepts exactly one connection inside its 60-second window, so
starting it before the Guardian reports listener readiness or before the
sender preflight passes can consume the only attempt. The execution challenge
is created once, copied privately to both real hosts, attested on each host
against its actual binary, and removed after evidence construction.

1. Obtain a separately approved, temporary direct UDP path from the sender host
   to one fixed Guardian UDP port. Restrict the path to the approved sender where
   infrastructure permits. If direct UDP is unavailable, stop. An SSH/TCP tunnel,
   relay, DNS route, same-host process, container or namespace is not equivalent
   two-host QUIC evidence.
2. On the Guardian host, apply this runbook's full Guardian configuration
   requirements without relaxation:

   - one owner-only `0700` identity directory; a generated identity is `0600`
     and an existing identity has no execute, group, or world bits;
   - an owner-only `0600` service config that preflight accepts with no
     unknown or unbounded fields;
   - distinct absolute paths for the identity, collector, ThreatHint-v1,
     ThreatHint-v2, and submission sockets;
   - collector and both ThreatHint verifier boundary sockets in an owner-only
     runtime directory with mode `0600`;
   - `threat_hint_v2_trusted_network_id = "testnet-10"`;
   - exactly the approved direct literal-IP/UDP/QUIC-v1 listener; no DNS,
     relay, TCP, or retry routes;
   - bounded health, ingress, startup, drain, and submission limits.

   Run `prometheus-guardian-p2p preflight`, then start the Guardian and wait
   for listener readiness (`ready: true` is listener readiness only, not
   Guardian authorization). Record the static transport `PeerId` privately;
   do not place it in public evidence.
3. On the sender host, keep the existing strict client config and add the
   explicit opt-in below. Use one canonical literal IP route whose trailing
   `PeerId` exactly matches `guardian_peer_id`:

```toml
enabled = true
network = "testnet10"
route_mode = "controlled-remote-testnet10"
guardian_peer_id = "<guardian-transport-peer-id>"
guardian_address = "/ip4/<approved-guardian-ip>/udp/<approved-port>/quic-v1/p2p/<guardian-transport-peer-id>"
identity_path = "/var/lib/prometheus/light-client/client.identity"
submission_timeout_secs = 60
```

4. Run `prometheus-client threat-hint preflight` first. It must report
   `single-static-controlled-remote-quic-peer` without creating the identity or
   dialing. If preflight fails, stop; do not start the boundary.
5. Create the execution challenge once, on one operator-controlled host, in a
   dedicated canonical owner-only `0700` directory that is separate from the
   Guardian socket runtime directory:

```bash
install -d -m 0700 /run/prometheus/gh-229-attestation
python3 scripts/gh229_execution_attestation.py create-challenge \
  --output /run/prometheus/gh-229-attestation/challenge.bin
```

   The command refuses symlinked or existing paths and emits only the fixed
   token `GH229_CHALLENGE_CREATED`. Copy the 32-byte file privately to an
   owner-only `0700` directory on the other real host over an
   already-authenticated operator channel, never through Git or any public
   channel, and keep it owner-only `0600` on both hosts.
6. Only now, on the Guardian host, create the dedicated owner-only runtime
   directory and start the committed Development boundary with one expected
   canonical payload digest; its 60-second window must cover exactly one
   submit:

```bash
mkdir -p /run/prometheus/gh-229
chmod 700 /run/prometheus/gh-229
python3 scripts/development_threat_hint_v1_boundary.py \
  --socket /run/prometheus/gh-229/threat-hint.sock \
  --receipt /run/prometheus/gh-229/receipt.json \
  --expected-sha256 '<lowercase-sha256-of-canonical-v1-payload>' \
  --status rejected \
  --timeout 60
```

   The boundary accepts exactly one owner-local AF_UNIX connection, writes one
   atomic owner-only redacted receipt and can return only `rejected` or `busy`.
   It cannot return `accepted` or `duplicate` and has no proof, membership,
   publication, chain or reward authority. The Guardian's `threat_hint_socket`
   must point at that socket.
7. Immediately run one `submit` from the sender. No retries are permitted.
8. A valid controlled run requires the sender to report `rejected` and the local
   Guardian receipt to report the same payload digest and `rejected`. This proves
   only one operator-attested delivery and non-authorizing acknowledgement. Host
   separation is not independently proven by the redacted public record.
9. On each real host, run `attest` against that host's actual binary: the
   client binary with `--role sender` on the sender host, and the Guardian
   binary with `--role guardian` on the Guardian host. Both runs use the same
   private challenge copy, the exact 40-lowercase-hex source commit, and the
   canonical payload digest:

```bash
python3 scripts/gh229_execution_attestation.py attest \
  --challenge /run/prometheus/gh-229-attestation/challenge.bin \
  --role sender \
  --source-commit '<exact-40-lowercase-hex-source-commit>' \
  --artifact /path/to/actual-binary \
  --payload-sha256 '<lowercase-sha256-of-canonical-v1-payload>'
```

   Each run emits one canonical compact JSON line containing only `role`,
   `challenge_sha256`, `artifact_sha256`, and
   `execution_attestation_sha256`. Map the outputs into the existing verifier
   schema: the shared `challenge_sha256` becomes `challenge_sha256`; the
   sender line's `artifact_sha256` and `execution_attestation_sha256` become
   `artifacts.client_sha256` and `execution_attestations.sender_sha256`; the
   Guardian line's become `artifacts.guardian_sha256` and
   `execution_attestations.guardian_sha256`; the shared `--payload-sha256`
   remains `delivery.payload_sha256`. These are operator attestations and are
   not independent host proof.
10. Stop both processes, remove the temporary UDP allowance, remove the
    private challenge file from both hosts, and verify the owned AF_UNIX
    socket is gone. Keep network identifiers, PeerIds, hostnames, paths, raw
    payloads and private receipts out of Git. Publish only a record accepted
    by the explicit verifier invocation below. The dated committed record is
    immutable evidence for its one bounded run, never a reusable placeholder:

```bash
python3 scripts/verify_gh229_multihost_evidence.py \
  --evidence docs/evidence/gh-229-controlled-two-host-2026-08-27.json
```

The repository unit tests validate this procedure's route and evidence policy.
They do not constitute a real two-host run. The dated redacted record proves
only one operator-attested controlled distinct-host delivery; public multi-host
Light Client operation remains unproven.

#### Execution attestation formula (GH-229)

`attest` computes one deterministic domain-separated digest over versioned
canonical binary framing:

```text
execution_attestation_sha256 = SHA-256(frame)

frame = "prometheus-gh229-execution-attestation" || 0x00 || 0x01 ||
        u8(n)  || role           ||   # ASCII "sender" (n=6) or "guardian" (n=8)
        u8(32) || challenge      ||   # raw 32 challenge bytes
        u8(20) || source_commit  ||   # raw 20 bytes from 40 lowercase hex
        u8(32) || artifact_hash  ||   # raw SHA-256 of the actual artifact bytes
        u8(32) || payload_hash        # raw SHA-256 of the canonical v1 payload
```

`u8(n)` is one unsigned length byte; every other field is raw bytes in the
fixed order above. The `0x00` terminator separates the domain string and the
`0x01` byte versions the framing. Because the role is inside the frame, the
sender and guardian attestations over otherwise identical inputs always
differ, which the evidence verifier requires.

6) Start processes

```bash
prometheus-guardian-p2p run --config /var/lib/prometheus/guardian-p2p/service.toml
```

- Start the existing authenticated collector before the sidecar, or within `collector_startup_timeout_secs`.
- Treat `ready: true` as listener readiness only, not Guardian authorization or public reachability.
- Monitor JSON-line `health`, listener, connection, reservation, circuit, inbound, outbound, and terminal events.
- Drain stdout continuously. JSON-line output uses a bounded dedicated writer; output backpressure or writer failure makes the service fail closed instead of blocking signal handling indefinitely.
- A collector outage returns `busy`; unsafe IPC ownership, framing, or ACK data fails closed.
- A v2 ingress outage returns `busy`; invalid canonical framing, wrong trusted
  network, unsafe IPC ownership, or malformed acknowledgements fail closed. The
  configured network is local trust and must match the governed Python policy.
- This procedure does not approve production proof artifacts or authorize
  semantic/actionable analysis, publication, chain activity, or rewards.
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
