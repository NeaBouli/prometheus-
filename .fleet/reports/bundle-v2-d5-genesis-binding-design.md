id: bundle-v2-d5-genesis-binding-design
status: ok (design proposal; pending Codex review/approval before any runtime acceptance change)
worker: claude
branch: agent/claude/bundle-v2-d5-genesis-binding-design (base 506cf01085cac7c1cbd54609155bf1ca28bed7d8)
architecture_node: MAP M1/MS-B; reviewed deployment manifest -> genesis covenant identity -> off-chain state acceptance
deliverables:
  - docs/architecture/d5-genesis-binding-design.md: traced call sites, precomputable vs evidence-bound identity, circular-dependency rules, versioned draft binding schema, validation order, statuses, matrix, findings, minimal implementation plan with paths.
  - scripts/silverc_genesis_binding_draft.py: non-executable draft validator (no CLI, no writes, no new crypto); every result stays blocked on covenant-id recomputation; evidence phase refused for non-promotable bundles.
  - scripts/test_silverc_genesis_binding_draft.py: 23 tests (validation matrix incl. lookalike, cross-network/bundle/role substitutions, duplicate ids/outpoints, missing/inconsistent anchors, altered plan, self/2-/3-cycles, topological order, operator claims rejected, raw-response tampering, acceptance lookalike/role/network, role table vs .sil headers, determinism, module non-executable).
  - modules/contracts/silverc/genesis-binding.draft.sample.json: synthetic sample plan (labels derived from fixed strings; not chain data), asserted equal to the test builder and NOT_EXECUTABLE.
  - Pointers in ms-b-contract-decisions.md (D5) and MAP.md.
key_results:
  - Covenant id = H(funding outpoint, [index, value, script version, script]); signatures and the binding excluded; consensus re-checks (WrongGenesisCovenantId). Deployer computes it before signing (lib.rs:1075-1091). Ids are precomputable; proof needs recomputation from reviewed fields plus stored public UTXO evidence.
  - Circularity: ids hash constructor args, so mutual embedding is unsatisfiable; trust edges must be a DAG with topological deployment. v2 has no trust edges today (no cross-contract calls, no co-spend checks) -> recommend amending D5 to off-chain binding now.
  - Gaps: no verifier reads covenant ids; H-001 evidence lacks the funding outpoint (canary id not independently recomputable; evidence stays frozen); client accepts any owner-signed manifest id without role registry.
decisions_for_codex: (1) deployment-specific constructor set/compiled identity (v2 manifest binds placeholder keys); (2) shared vs per-contract governance key (fixtures: distinct placeholders); (3) amend D5 wording; (4) H-001 not a D5 anchor.
proposed_implementation (order, needs approval): offline Rust covenant-id command reusing prepare_genesis output construction + kaspa_consensus_core covenant_id (lib.rs, main.rs); evidence capture of funding outpoint/covenant id/raw UTXO (NodeObservation, verify_silverc_deploy_receipt_evidence.py); Python binding replaces RECOMPUTE_BLOCKER; client acceptance allowlist in rule_observation.rs step 7 as separate brief.
tests:
  python3 -m unittest scripts.test_silverc_genesis_binding_draft -> 23 OK
  python3 -m unittest discover -s scripts -p 'test_*.py' -> 438 OK
  ruff check/format; mypy --strict on the validator; mypy on the test -> clean
  public gates (hygiene, claims, status, memory) -> PASS
  no hosted dispatch (per brief)
risks: line references from code tracing (rusty-kaspa v2.0.1 cfafeb4, deployer) should be re-checked at implementation time; validator is a design artifact, not wired into any tool.
not changed: contract logic, Rust code and pins, H-001/proof/toolchain pins, evidence, tokenomics, slash, commit-reveal; no signing, wallet, chain, host, deploy, nested agents, merge.
