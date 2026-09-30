# A4 — Fail-closed client runtime gate (PRM-03)

Architecture boundary: `modules/client`, MAP hop H1 immediately before
`ThreatHintSubmitConfig::submit`; no new module, protocol, or wire format.

## Objective and scope

- Re-verify PRM-03 against the current branch before changing code. If invalid,
  return `partial` with evidence and no speculative patch.
- Make the existing `PROMETHEUS_RUNTIME` interpretation fail closed: missing,
  empty, malformed, `beta`, or `mainnet` must never permit development-only
  ThreatHint submission. Preserve the documented Development/Testnet-10 path.
- In `modules/client/src/network/p2p.rs`, reject disallowed runtime modes before
  DNS, socket, QUIC, peer connection, file mutation, or other network activity.
- Reuse the existing runtime parser/gate. Do not add a second parser, CLI flag,
  retry, wrapper, protocol change, contract change, or architecture layer.
- Limit edits to the existing runtime-mode implementation, `network/p2p.rs`,
  and their focused Rust tests. Update the architecture map only if the actual
  hop/status changes.

## Acceptance

- Add regression tests proving fail-closed default/malformed/beta/mainnet and
  proving rejection occurs before any network attempt; keep allowed dev/test
  behavior covered.
- Run `cargo fmt --check`, focused client tests, complete client tests, and
  `cargo clippy -- -D warnings` for the affected package(s).
- Preserve KAS/PROM, commit-reveal, wallet, chain, deployment, and public claims.
- Report exact commands/results in `.fleet/reports/a4-client-runtime-gate.md`;
  no PR merge, main push, deploy, external message, secrets, or subagent.
