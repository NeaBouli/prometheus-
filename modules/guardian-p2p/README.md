# Prometheus Guardian P2P

This workspace crate is the transport-only Guardian ballot carrier introduced
by GH-42. It uses the rust-libp2p 0.56 component set without the umbrella crate,
so unused optional DNS/mDNS dependencies do not enter the audited lockfile.

## Implemented Boundary

- QUIC direct transport and `/prometheus/guardian-ballot/1.0.0` request/response
- Exact opaque ballot bytes with a hard 8192-byte limit
- One-byte `accepted`, `duplicate`, `rejected`, or `busy` network result
- Static peer multiaddresses, Identify, Ping, AutoNAT, relay client, and DCUtR
- Global request, per-connection stream, connection, and timeout limits
- Owner-only AF_UNIX bridge to the Python authenticated-ballot collector
- Digest-bound canonical local acknowledgements

`PeerId` is transport metadata only. This crate does not assign Guardian IDs,
create membership, verify BIP340 ballots, hold signing keys, modify reputation,
submit proposals, or write chain state. Those application checks remain in the
Python collector and the committed local `BallotSession`.

The event-driven production seam is
`GuardianP2p::next_sidecar_event(&UnixBallotIngress)`. It forwards every inbound
frame to the local collector before answering the remote peer. Local timeout or
I/O failure returns `busy`; an unsafe socket or invalid local ACK returns
`rejected`.

## Not Yet Proven

- Public relay reservation and relay-only delivery
- AutoNAT classification and DCUtR upgrade in an operated network
- Broad peer discovery; mDNS is excluded while the compatible dependency path
  carries unresolved RustSec advisories
- Trusted membership/key assignment, PeerId rotation, or Sybil resistance
- Guardian-to-Validator proposal transport or on-chain ensemble attestation
- A packaged operator service with persistent transport-identity provisioning

## Verification

```bash
cargo test -p prometheus-guardian-p2p
cargo clippy -p prometheus-guardian-p2p --all-targets -- -D warnings
cargo audit
```

Tests cover frame bounds, outbound admission, exact two-node QUIC transfer,
owner-only Unix socket validation, digest mismatch rejection, and the complete
QUIC-to-collector-to-network-ACK path with ephemeral test identities.
