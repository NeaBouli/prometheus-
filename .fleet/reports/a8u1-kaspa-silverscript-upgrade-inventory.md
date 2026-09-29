id: a8u1-kaspa-silverscript-upgrade-inventory
status: ok
worker: claude (Codex stand-in, thread 019f3d96)
branch: agent/claude/prometheus-standin-20260930
base: 60ee6db (PR #284 head)
summary: Compatibility inventory for the candidate upgrade Rusty Kaspa v2.0.1 -> v2.1.0 and SilverScript d25bd34 -> v1.0.0, governed by the A8 pin gate. Result: no coherent upgrade is currently possible; the active pins stay unchanged. No product file was changed (spike reverted).

findings:
  F1 (blocking, upstream): SilverScript d25bd34 itself depends on rusty-kaspa tag v2.0.1 (kaspa-consensus-core, -txscript, -txscript-errors, -hashes, ...). Bumping only our workspace to v2.1.0 produces a split lock graph (11 v2.0.1 + 22 v2.1.0 kaspa packages), which the A8c policy rejects by design (">1 distinct Kaspa source").
  F2 (blocking, upstream): SilverScript v1.0.0 (tag 3ed97333, = master head 2026-09-09) pins rusty-kaspa rev a41a333b (2026-08-02), an untagged commit 13 commits behind v2.1.0 (01b532e8). Its Cargo.toml comment says the rev pin will be replaced by a release tag once a rusty-kaspa release contains kaspa-txscript-zk-sdk; v2.1.0 now contains it, but no SilverScript commit/PR does this yet (checked open PRs 2026-09-30). Therefore "v2.1.0 + SilverScript v1.0.0" cannot be one graph without [patch]/[replace], which the A8c policy forbids for pinned sources.
  F3 (API break, our code): With v2.1.0, only prometheus-silverc-deployer fails to compile (8 errors); client, guardian-p2p, threat-hint, threat-proof, validator compile unchanged (cargo check --workspace --all-targets --locked, split graph).
    - modules/silverc-deployer/src/lib.rs:814,1154,1473,1477,1501: `Params::toccata_activation` removed (v2.1.0 collapses Toccata activation into unconditional post-Toccata logic, upstream #1082..#1101).
    - modules/silverc-deployer/src/lib.rs:966: `Params::mempool_block_mass_cofactors` removed/renamed.
    - modules/silverc-deployer/src/oracle.rs:685,1056: `EngineFlags::covenants_enabled` removed (covenant verification now unconditional).
  F4 (schema impact): `toccata_activation_daa_score` is a serialized field of the deployer signing request / receipt structs (lib.rs:224, 342) and is checked against consensus params (lib.rs:814). A v2.1.0 port therefore changes an operator-record schema, not just code; H-001 evidence (docs/evidence/gh-9-*) stays immutable and must keep verifying with the v2.0.1 tooling. This needs a versioned schema decision (Codex/Gio), not a silent field drop.
  F5 (identity): threat-proof relation identity pins (modules/threat-proof/src/lib.rs:29-30, guardian-node/jaeger/relation_manifest_v2.py:46-47) bind v2.0.1/cfafeb4 as proof-artifact identity. The A8c policy correctly keeps them separate from active build pins; an upgrade of active pins must NOT move them.

recommendation:
  1. Keep active pins (v2.0.1 / d25bd34). No production relevance yet (production false, no deployments).
  2. Re-check upstream weekly: the unblock condition is a SilverScript commit that depends on rusty-kaspa tag v2.1.0 (or later). Then do A8u2 = one PR: Cargo.toml + Cargo.lock + toolchain-pins.json active pins + deployer port + versioned request/receipt schema (v2) with v1 kept verifiable for H-001.
  3. Alternative (not recommended): adopt rusty-kaspa rev a41a333b for the whole workspace to match SilverScript v1.0.0. Rejected: untagged pre-release commit, misses v2.1.0 fixes (bip32 constant-time equality, P2P limits), and requires relaxing the policy's tag requirement.
  4. SilverScript v1.0.0 language/ABI changes (64 commits, 244 files since d25bd34; stricter resource/initial-state validation #245/#246) will likely change compiled artifacts; recompiling the seven contracts under v1.0.0 is part of A8u2 and needs the MS-B `.ss` vs `.sil` decision first.

tests: cargo check --workspace --all-targets --locked against v2.1.0 (spike, reverted) -> 8 errors, all in silverc-deployer; git diff after revert: empty for Cargo.toml/Cargo.lock.
risks: upstream timing unknown; until aligned the project builds on v2.0.1, which is a supported mainnet Toccata release.
security: none introduced (read-only inventory). Note: v2.1.0 fixes kaspa-bip32 constant-time private-key equality; our code uses kaspa-bip32 only in development/testnet paths — review owed to Codex whether any path compares private keys.
next: Codex decides whether to track the upstream unblock as an issue; Claude continues MS-A with GH-279 (PRM-09).
