id: bundle-v2-early-gate-correction
status: ok (pending Codex review; no hosted CI until Codex coordinates)
worker: claude
branch: agent/claude/bundle-v2-early-gate-correction (base af24d3f546fd7db612c541c5b6a553759f79084a)
architecture_node: silverc bundle selection -> operator input loading
finding (confirmed): 9 entrypoints called bundle_root_from_args (archive read/extract, temp dir) before require_promotable: build_metrics_oracle_operator_procedure, build_silverc_deploy_operator_procedure, build_silverc_operator_receipts, stage_metrics_oracle_status, stage_silverc_deployment_status, verify_metrics_oracle_tx_evidence, verify_metrics_oracle_tx_result, verify_silverc_deploy_receipts, verify_silverc_deploy_receipt_evidence. Already correct: build_silverc_operator_handoff and build_metrics_oracle_tx_request (gate is the first statement after parse_args). Static draft tools (smoke, preflight, build/verify deploy requests) intentionally accept v2 and are unchanged.
fix: in the 9 entrypoints, bundle selection + require_promotable moved to the first statement after parse_args, before archive/request/receipt/report reads and before any output or temp-directory creation. No other logic changed; v1 path identical (same calls, same order after the gate). Pins, Rust, evidence, contracts untouched.
regression: scripts/test_silverc_early_gate.py (wired into the CI separation step). Parameterized over all 11 refusing entrypoints x {missing, malformed} inputs: module helpers (bundle_root_from_args, validate_manifest, load_json, load_report_json, validate_report, ensure_public_file, run, write_*) and primitives (open, Path.open/read_*/write_*/mkdir, tarfile.open, tempfile.mkdtemp/TemporaryDirectory, shutil.copy*) raise if called; v2 must raise "non-promotable draft" and create no output. v1 control proves the patched helpers are each tool's real first read.
tests:
  python3 -m unittest scripts.test_silverc_early_gate -> 2 tests (22 v2 subtests + 11 v1 controls) OK
  same test against an af24d3f copy -> FAILED (failures=18) = exactly the 9 tools x 2 input kinds; handoff and oracle tx request pass (delta proven)
  python3 -m unittest scripts.test_silverc_bundles scripts.test_silverc_manifest_build_pin -> OK
  python3 scripts/test_silverc_bundle_profiles.py (v1/v2 archives, deployer) -> OK
  python3 -m unittest discover -s scripts -p 'test_*.py' -> 415 OK (413 + 2 new)
  ruff check/format, mypy on changed scripts -> clean except pre-existing verify_silverc_deploy_receipts.py:162 (unchanged line)
  public gates (hygiene, claims, status, memory) -> PASS
  local replay h001-silverc-runtime (incl. new regression in the separation step) -> 16/16 PASS; v1 operator chain unchanged
