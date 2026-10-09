verdict: ok (proposed documentation scope only; publishing checks pending)
reviewer: Codex self-review, owner-directed execution
- Verified worker source3e94ce0: candidate consistency and unconditional accept_state refusal are distinguished from public main and chain acceptance.
- Exact Cargo.lock upstream revision used; covenant derivation is reused, not reimplemented. RPC/header/DAA limitations are explicit.
- Reviewed source independence, operator/reviewer provenance, network/bootstrap identity, stale/reorg/pruned/successor handling, expiry at use, strict shapes and non-promotable early rejection.
- No claims of independent review, production, deployed v2, achieved timing, state authority or active PROM. No private findings, endpoints, identities or signed transactions included.
- Matrix is explicitly a future acceptance specification, not executed test evidence; model selection and numerical policy stay proposed.
- Current gate is not made conditional on a self-asserted result or status. A later acceptance implementation and client allowlist require their own review.
- Diff is limited to the existing architecture node's documentation and coordination. No contract/source/dependency/workflow/fixture/evidence change.
- Local target tests could not launch under the requested memory isolation; reported honestly, no permissive retry. Hosted checks remain mandatory before merge.
- This is not independent/full contract security acceptance. Codex Security remains NOT RUN; product integration and owner-gated actions remain separate.
