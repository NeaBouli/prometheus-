id: bundle-v2-d5-offline-covenant-id
status: ok (pending Codex review; no hosted dispatch until Codex coordinates)
worker: claude
branch: agent/claude/bundle-v2-d5-offline-covenant-id (base eaf8eb77b76f6b820d712b80794ca51db891148a)
architecture_node: MAP M1/MS-B; reviewed genesis fields -> existing consensus covenant_id helper -> offline calculated identity
change:
  - modules/silverc-deployer/src/lib.rs: extracted `unbound_genesis_contract_output` + `genesis_covenant_id` (thin wrapper over the pinned kaspa_consensus_core::hashing::covenant_id) and used them in prepare_genesis (same construction, byte-identical result); new `parse_funding_outpoint` (canonical lowercase txid, canonical decimal u32 index), `load_artifact_for_calculation` (expected artifact/script SHA-256 from an already validated manifest, secret-field rejection, non-empty script), `calculate_genesis_covenant_id` -> `CovenantIdCalculation` (kind prometheus.silverc.genesis.covenant_id_calculation, classification [NOT_CHAIN_EVIDENCE, NOT_DEPLOYMENT_AUTHORIZATION], contract/artifact/script identity, funding outpoint, value, output index 0, authorizing input 0, contract script public key, covenant id). No keys, network, funding UTXO, transaction, request, signing request, receipt or broadcast.
  - modules/silverc-deployer/src/main.rs: subcommand `calculate-covenant-id --artifact --expected-artifact-sha256 --expected-script-sha256 --funding-outpoint --genesis-output-value-sompi --calculation-out`; collision gate before any read; exclusive create via existing `create_public_json` (refuses overwrite).
  - prepare_genesis acceptance, release pins (FULL_BUNDLE_MANIFEST_SHA256 v1), profile gates: unchanged; v2 execution still rejected.
  - D5 design wording corrected (docs/architecture/d5-genesis-binding-design.md): raw RPC + own hash = consistency, not provenance/consensus truth; trusted-source model required, evidence acceptance blocked for its own block; cycles prohibited by policy (fixed point computationally infeasible, not proven impossible); H-001 record lacks the D5 anchor, external reconstruction not claimed impossible; Codex decisions recorded in the status line. Draft blocker text updated. MAP row updated.
tests (exact commands; CARGO_TARGET_DIR shared with an existing deployer build because of low disk):
  cargo test -p prometheus-silverc-deployer --locked -> lib 56 OK (6 new), calculate_covenant_id 2 OK (new), genesis_output_collisions 6 OK (new subcommand added to the table)
    parity: calculation == prepare_genesis covenant id/script public key/outpoint/index for both fixtures
    vector: 3a81b23246d64864e295fb5aa5e1cc36d45711fd402a602fb7ef765ec8d21b8a equals the pre-existing deterministic_genesis_interoperability_vector (pinned before this change) -> independent vector; prepare txid/sighash vectors unchanged
    sensitivity: funding txid, index, value, script, script version, output index each change the id; the covenant binding itself does not
    fail-closed: malformed/non-canonical/overflow outpoints, zero value, bad/uppercase verified hash, empty script, artifact/script hash mismatch, secret field; CLI: overflow/negative value, no output file on rejection, refuses overwrite with output unchanged
    gate: non-v1 manifest still "release-manifest binding mismatch"
  cargo fmt --all -- --check -> OK; cargo clippy -p prometheus-silverc-deployer --all-targets --locked -- -D warnings -> clean
  deployer --help + calculate-covenant-id --help: CI forbidden secret-flag grep -> no match
  manual: real v1/v2 GuardianReputationState (unchanged contract) -> same id 342c03cf…; RuleStorageState (changed in v2) -> different ids (8748fa83… vs 0193877f…), all classified
  python3 scripts/test_silverc_bundle_profiles.py (new deployer binary) -> OK (v2 prepare still rejected, no export)
  python3 -m unittest scripts.test_silverc_genesis_binding_draft scripts.test_silverc_bundles scripts.test_silverc_early_gate -> OK
  python3 -m unittest discover -s scripts -p 'test_*.py' -> 438 OK
  public gates (hygiene, claims, status, memory) -> PASS
  not run locally: workspace-wide cargo test/clippy (other crates unchanged; disk ~2.7 GB free) -> covered by the coordinated hosted run
risks: the calculation accepts draft artifacts by design (classification forbids treating the result as evidence or authorization); funding-amount/fee checks remain only in prepare_genesis.
not changed: contract logic, pins, evidence, Python acceptance, client allowlist, evidence capture; no wallet, chain, host, deployment, nested agents.
