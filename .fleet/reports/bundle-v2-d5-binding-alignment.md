id: bundle-v2-d5-binding-alignment (C1, self-proposed under Gio's 2026-10-02/03 rule; announced to Codex)
status: ok (pending Codex review; no hosted dispatch until Codex coordinates)
worker: claude
branch: agent/claude/bundle-v2-d5-binding-alignment (base 61549b19055f84ee2e83dd40d209d8a229e2522b)
architecture_node: MAP M1/MS-B; Rust D5 evidence candidate -> Python draft binding (plan context), no activation
change:
  - scripts/silverc_genesis_binding_draft.py: evidence phase now consumes Rust `prometheus.silverc.d5.genesis_evidence_candidate` v1 documents instead of the earlier ad-hoc raw-response format (removed: source_kind, raw_response, confirmations, block_hash fields). New `verify_candidate_document` (exact key sets, constants mirroring lib.rs, fixed output index, all relationships, DAA chronology/depth, snapshot + candidate hashes) and `_bind_candidate` (plan context: network, role contract, funding outpoint, genesis value, calculated id == predicted id). Result always carries `independently_confirmed: false` plus TRUST_BLOCKER; `accept_state` now additionally requires `independently_confirmed is True`, which the draft never sets -> every real result is refused. RECOMPUTE_BLOCKER unchanged; not wired into any tool or client.
  - modules/silverc-deployer/tests/fixtures/d5-evidence-candidate.synthetic.json: candidate produced by the Rust builder (deterministic synthetic fixture); Rust test `d5_candidate_matches_cross_language_fixture` asserts equality + context verification; Python verifies the same bytes and pins its constants to it. Rust production code unchanged.
  - docs/architecture/d5-genesis-binding-design.md: sections 4/5/6/8 updated to the candidate format and the acceptance refusal.
tests (exact commands; shared CARGO_TARGET_DIR):
  python3 -m unittest scripts.test_silverc_genesis_binding_draft -> 27 OK (evidence matrix rewritten: self-consistent context substitutions network/contract/funding/value/id, internal inconsistencies incl. future DAA and non-fixed index, hash tampering, status/trust/source upgrades, unknown/missing/legacy fields, NOT_CONFIRMED for real results, hypothetical confirmed result for lookalike/role/network logic, cross-language fixture verify + tamper)
  cargo test -p prometheus-silverc-deployer --locked -> lib 66 OK (1 new fixture parity test), calculate_covenant_id 2 OK, genesis_output_collisions 6 OK; cargo fmt --check OK; cargo clippy -p prometheus-silverc-deployer --all-targets -D warnings -> clean
  python3 -m unittest discover -s scripts -p 'test_*.py' -> 442 OK
  ruff check/format; mypy --strict on the validator; mypy on the test -> clean
  public gates (hygiene, claims, status, memory) -> PASS
risks: C1 was self-proposed (Codex had paused activation tasks until the independent review); it prepares, does not activate. If Kimi's review changes the candidate design, this alignment follows.
not changed: Rust production code, pins, evidence, client, acceptance activation; no network/chain/signing/deploy.
