# K2: D5 trusted-source variants and acceptance specification

Owner: Codex, continuing the existing completion plan on 2026-10-10.
Mode: owner-directed independent execution; Claude remains paused.
Base: main `251307a4dbcd76b7c7be2f770591082f758fd6b5`.
Worker evidence: C2 `3e94ce0fa81591d2a0e23758dfc46a735a8b8a92`, unmerged.
Architecture node: MAP M1/MS-B; reviewed plan -> genesis identity ->
observed candidate -> closed off-chain acceptance.

## Scope

Produce a proposed source-trust design, not a runtime trust decision or a
second implementation. Reuse the delivered D5 record and candidate format.
Document source independence, network identity, consensus/UTXO limits,
freshness, reorgs, evidence provenance, policy pins and review boundaries.

Allowed files: this brief; `docs/architecture/d5-trusted-source-model.md`;
`docs/architecture/d5-trust-boundary.puml`; a bounded pointer in
`docs/architecture/MAP.md`; this task's report and append-only PLAN/ACTION_LOG.

No contract, source, fixture, bundle, dependency, workflow, client, signature,
wallet, endpoint, network capture, deployment or acceptance change. No worker
dispatch or new external source-code transfer. No private finding details.

## Acceptance

1. Separate verified current behavior from proposed variants and decisions.
2. Explain why hashes, source labels, two URLs, headers or DAA depth alone do
   not establish independent chain confirmation.
3. Specify fail-closed validation order and at least 20 adverse-case criteria.
4. Preserve unconditional `NOT_CONFIRMED`, non-promotable v2 and frozen H-001.
5. Provide a dependency-ordered implementation backlog without activating it.
6. Verify references, documentation hygiene, public/status/pin consistency,
   diff scope and relevant documentation tests. No expensive unchanged build.
7. Review the security design locally, explicitly not independent acceptance;
   publish through a normal PR with actual checks, no main/protection bypass.

Model selection, policy values, implementation security review, source access
and live capture remain separate gates. Complete only this documentation block.
