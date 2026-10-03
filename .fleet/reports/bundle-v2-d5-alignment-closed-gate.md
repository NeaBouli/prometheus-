id: bundle-v2-d5-alignment-closed-gate
status: ok (pending Codex review; no hosted dispatch until Codex coordinates)
worker: claude
branch: agent/claude/bundle-v2-d5-alignment-closed-gate (base f6d3dc6 = C1 code 2595ce8 + handover docs)
architecture_node: Rust candidate schema -> Python draft validation -> closed acceptance boundary
fix_1: verify_candidate_document validates schema_version with the existing non-boolean unsigned-integer helper (_uint, u32 range) before comparing to 1, matching Rust (bool, float and string rejected as CANDIDATE_SCHEMA).
fix_2: accept_state is an unconditional closed gate (NoReturn): always BindingError NOT_CONFIRMED for genuine, forged or caller-modified results; no prepared activation switch. Results still carry independently_confirmed=false for diagnostics only. Role/network/lookalike substitutions remain rejected at the candidate-to-plan binding.
tests:
  python3 -m unittest scripts.test_silverc_genesis_binding_draft -> 27 OK
    schema_version True / 1.0 / "1" / None / -1 / 2 with rehashed candidates -> CANDIDATE_SCHEMA (not a hash failure)
    accept_state refuses the genuine result and 6 forged results (independently_confirmed=True, empty blockers, executable=True, altered status, self-constructed dict, empty dict) for observations with and without role -> NOT_CONFIRMED
    removed: positive test for a hypothetical confirmed result
  delta check against 2595ce8: old accepted schema_version True and 1.0 and returned "rule_storage" for a forged result; new rejects all three
  python3 -m unittest discover -s scripts -p 'test_*.py' -> 442 OK
  ruff check/format clean; mypy --strict reports no finding in the validator (the only strict finding is pre-existing in imported scripts/smoke_silverc_artifacts.py:340); mypy on the test clean
  public gates (hygiene, claims, status, memory) -> PASS
  Rust: no change, no rebuild
not changed: Rust code, fixture, pins, client, activation; no external review dispatch, nested agents or deployment.
