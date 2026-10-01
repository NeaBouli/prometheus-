id: bundle-v2-d5-evidence-capture
status: ok (pending Codex review; no hosted dispatch until Codex coordinates)
worker: claude
branch: agent/claude/bundle-v2-d5-evidence-capture (base ea7327740234fb2dca33fb48a9db17321a13a1fe)
architecture_node: MAP M1/MS-B; existing NodeObservation -> bounded public genesis evidence candidate
call_site_map: main.rs Command::Observe -> rebuild_and_verify -> lib.rs observe_deployed_utxo (now a wrapper over observe_deployed_utxo_entry: same inspect_node, get_utxos_by_addresses, get_block_dag_info, deployed_contract_entry checks, same NodeObservation) -> new pure build_d5_evidence_candidate(signing_request, typed entry, virtual DAA) -> verify_d5_evidence_candidate. No second RPC client; oracle path untouched.
schema_delta:
  - NodeObservation: unchanged (fields, values, file). observe without the new flag: unchanged behaviour.
  - New optional CLI output `observe --d5-evidence-candidate-out` -> `prometheus.silverc.d5.genesis_evidence_candidate` v1 (structs D5EvidenceCandidate / D5PreparationInputs / D5ObservedUtxoSnapshot / D5TrustModel, all deny_unknown_fields): status OBSERVED_NOT_INDEPENDENTLY_CONFIRMED; classification NOT_CHAIN_PROOF / NOT_D5_ACCEPTANCE / NOT_DEPLOYMENT_AUTHORIZATION; trust model single_operator_configured_node, independent_confirmation false, missing independent checks listed, snapshot note (normalized allowlist, not raw wire response, hash = integrity/consistency only); preparation (source: validated_preparation_inputs_not_chain_proof) incl. funding outpoint and calculated covenant id; observed (source: configured node typed entry) outpoint/amount/script/covenant id/DAA/coinbase; observed_snapshot_sha256 + candidate_sha256 (canonical JSON); explicit relationship list.
  - Not stored: RPC endpoint/credentials, deployer/contract address, headers, logs, timestamps, wallet/operator metadata.
  - v1 requests, signing requests, receipts, H-001 evidence, pins: unchanged.
  - Docs: d5-genesis-binding-design.md section 9 + step 2 status; MAP row.
tests (exact commands; CARGO_TARGET_DIR shared with an existing deployer build because of low disk):
  cargo test -p prometheus-silverc-deployer --locked -> lib 62 OK (6 new D5 capture tests), calculate_covenant_id 2 OK, genesis_output_collisions 6 OK (observe now lists the candidate output in all collision cases)
    capture: fields/sources bound, deterministic, signing request unchanged, calculated id = pinned vector 3a81b232…, DAA depth
    secrets: reject_secret_fields passes; observed key allowlist exact; rpc_url/deployer/contract address/sighash/observed_at/headers/endpoint absent
    mismatch: missing covenant anchor, observed id, outpoint txid/index, value, script, coinbase, invalid network id
    substitution: funding outpoint substitution and calculated-id substitution (with matching lookalike UTXO) rejected via recalculation
    tamper: snapshot hash, candidate hash, DAA depth, status upgrade, independent_confirmation=true, classification change, source relabel, consistent id swap
    json: unknown, duplicate and missing fields rejected
  cargo fmt --all -- --check -> OK; cargo clippy -p prometheus-silverc-deployer --all-targets --locked -- -D warnings -> clean
  deployer --help / observe --help: CI flag checks and forbidden secret-flag grep -> OK
  python3 scripts/test_silverc_bundle_profiles.py (new binary) -> OK
  python3 -m unittest discover -s scripts -p 'test_*.py' -> 438 OK
  public gates (hygiene, claims, status, memory) -> PASS
  no live RPC: all capture tests use synthetic typed entries; workspace-wide cargo test/clippy left to the coordinated hosted run (disk ~2.5 GB)
remaining_gates: trusted-source model and independent confirmation (second source, reviewer capture, header cross-check, network identity); step (c) Python binding alignment/activation; step (d) client allowlist; full contract security acceptance; D1-D7 open; no v2 promotion.
