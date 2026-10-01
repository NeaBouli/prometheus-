id: bundle-v2-d5-capture-context-correction
status: ok (pending Codex review; no hosted dispatch until Codex coordinates)
worker: claude
branch: agent/claude/bundle-v2-d5-capture-context-correction (base 20ff442ee43b42ae0ee2d84a9b70661037d0e590)
architecture_node: MAP M1/MS-B; validated preparation -> observed UTXO -> evidence candidate verification
fix_1 (DAA chronology): build_d5_evidence_candidate and verify_d5_evidence_candidate use checked_sub and reject observed.block_daa_score > observed_virtual_daa_score ("genesis DAA score is above the observed virtual DAA score"); equal scores remain a valid zero depth. NodeObservation (v1) keeps its existing saturating depth unchanged.
fix_2 (context binding): verify_d5_evidence_candidate(candidate, validated_context: &SigningRequest) - context is mandatory (single verifier, no optional/default path); every exported preparation field (network_id, contract_name, request_sha256, signing_request_sha256, funding_outpoint, genesis_output_value, contract_output_index, contract_script_public_key, calculated_covenant_id vs covenant_id, expected_deploy_tx_id vs unsigned_transaction_id) must equal the context before acceptance; contract_output_index must equal CONTRACT_OUTPUT_INDEX. build passes the signing request from rebuild_and_verify. No new serialized fields; signing/request identities and the signed transaction are not serialized; NodeObservation and no-flag observe unchanged.
tests (exact commands; shared CARGO_TARGET_DIR, no workspace rebuild):
  cargo test -p prometheus-silverc-deployer --locked -> lib 65 OK (3 new), calculate_covenant_id 2 OK, genesis_output_collisions 6 OK
    DAA: equal scores -> depth 0 valid; future score rejected at build; future score with both hashes recomputed rejected at verify; altered scores with rehash accepted only when chronology and depth agree
    context: substituted valid network (mainnet), contract role, request hash, signing-request hash, funding outpoint (+recomputed id), expected deploy txid, script (+id), value (+id) - each candidate is built and verified self-consistently against its own substituted context (observed fields and both hashes consistent) and rejected against the original validated context; matching context accepted
    fixed index: context with output index 1 (+id, matching observed UTXO) rejected
    existing capture/tamper/json/secret tests unchanged except the id-swap case now fails at the context check
  cargo fmt --all -- --check -> OK; cargo clippy -p prometheus-silverc-deployer --all-targets --locked -- -D warnings -> clean
  deployer help secret-flag grep -> OK
  python3 scripts/test_silverc_bundle_profiles.py (new binary) -> OK
  python3 -m unittest discover -s scripts -p 'test_*.py' -> 438 OK
  public gates (hygiene, claims, status, memory) -> PASS
remaining_gates: unchanged from bundle-v2-d5-evidence-capture (trusted-source model/independent confirmation, steps c/d, contract security acceptance, D1-D7).
