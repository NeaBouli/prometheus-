id: msb-constructor-semantics-review
worker: claude (stand-in orchestrator, Gio-authorized 2026-10-10; Codex standby)
base: main 3cbb9355b4e29f93495234dc2960da8ef08b608a; source under review: held Draft PR #293 24980e6ddaccfdfa8d09eddb78cbd3675d1afe67 (read-only)
architecture_node: MAP M1/MS-B — deployment constructor set -> compiled identity -> genesis value/state (acceptance block steps 1-2)

Goal: complete MS-B acceptance-block steps 1 and 2 as analysis and documentation only, reusing the
finished static constructor intake (7 contracts, 86 parameters, ABI/argument hashes, role headers,
12 key slots). No repeat of the intake, no new implementation, no contract/fixture/pin change.

1. Per contract and constructor field: semantic meaning, unit (KAS, sompi, PROM accounting, bps,
   DAA score, count, bool, key), the state-layout slot it initialises, the value-backing equation it
   participates in, the valid genesis value or range, timing anchors it depends on, and cumulative
   counter bounds at genesis. Use public synthetic boundary reasoning only; mark each statement as
   derived from source (file:line) or as an assumption.
2. Role-to-key topology record: which key kind (governance/attestation, metrics oracle, validator,
   guardian, recipient/donor/developer/proposer placeholders) each slot expects, which slots must be
   equal across contracts under the current draft, and the distinction between placeholder compiled
   fixtures and a reviewed future deployment constructor set. No keys requested, collected or named.
3. State explicitly what changing constructor bytes implies (new scripts, covenant ids, compiled
   expectation and manifest pin; separate reviewed compiled-identity revision).

Outputs: private detailed report under the owner-only Codex documents folder (0600) with source
references; public generic summary on #276 and a repository document only if it contains no
unpublished security detail. Prior decisions stay: no donation cap, no constant removal now.

Acceptance: every one of the 86 parameter slots covered exactly once; each claim sourced or marked
as assumption; owner decisions listed, not taken; public gates pass if a repo file changes.
Disk is tight (about 1 GB free): no Rust/runtime builds in this block.
Not in scope: D1-D7 adoption, key ceremony, deployment constructor bytes, D5 activation, Kimi or
Codex Security dispatch, merge, release, chain, wallet or infrastructure actions.
