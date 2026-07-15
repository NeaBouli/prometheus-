#!/usr/bin/env python3
"""End-to-end regression checks for the non-promotable H-001 canary profile."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from hashlib import sha256
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEPLOYER = "kaspatest:qptestpreflight000000000000000000000000000000000"
ORACLE_KEY = "11" * 32
CANARY_PROFILE = "testnet-10-validator-staking-h001"
RESOLVER = "kaspa-resolver://public"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    return parser.parse_args()


def run(*args: str, expect_success: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        [sys.executable, *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if expect_success and proc.returncode != 0:
        raise AssertionError(f"command failed: {' '.join(args)}\n{proc.stdout}\n{proc.stderr}")
    if not expect_success and proc.returncode == 0:
        raise AssertionError(f"command unexpectedly passed: {' '.join(args)}")
    return proc


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def write(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def rehash(value: dict[str, Any], key: str) -> None:
    value.pop(key, None)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    value[key] = sha256(encoded).hexdigest()


def main(args: argparse.Namespace) -> int:
    archive = str(args.archive.expanduser().resolve())
    with tempfile.TemporaryDirectory(prefix="prometheus-h001-canary-test.") as tmp:
        root = Path(tmp)
        canary_requests = root / "canary-requests"
        canary_set = root / "canary-request-set.json"
        canary_verification = root / "canary-request-verification.json"
        canary_procedure = root / "canary-procedure.json"

        run(
            "scripts/preflight_silverc_deploy.py",
            "--archive",
            archive,
            "--deployment-profile",
            CANARY_PROFILE,
            "--network",
            "testnet",
            "--rpc-url",
            RESOLVER,
            "--deployer-address",
            DEPLOYER,
            "--plan-out",
            str(root / "canary-preflight.json"),
        )
        preflight = load(root / "canary-preflight.json")
        assert preflight["deploy_supported"] is True
        assert preflight["operator_inputs"]["metrics_oracle_pubkey_present"] is False

        run(
            "scripts/build_silverc_deploy_requests.py",
            "--archive",
            archive,
            "--deployment-profile",
            CANARY_PROFILE,
            "--out-dir",
            str(canary_requests),
            "--network",
            "testnet",
            "--rpc-url",
            RESOLVER,
            "--deployer-address",
            DEPLOYER,
            "--request-set-out",
            str(canary_set),
        )
        run(
            "scripts/verify_silverc_deploy_requests.py",
            "--archive",
            archive,
            "--request-set",
            str(canary_set),
            "--requests-dir",
            str(canary_requests),
            "--summary-out",
            str(canary_verification),
        )
        request_set = load(canary_set)
        request = load(canary_requests / "01-ValidatorStakingH001.deploy-request.json")
        verification = load(canary_verification)
        rust_operator = (ROOT / "modules/silverc-deployer/src/lib.rs").read_text(encoding="utf-8")
        rust_manifest = re.search(
            r'FULL_BUNDLE_MANIFEST_SHA256: &str =\s*"([0-9a-f]{64})"',
            rust_operator,
        )
        assert rust_manifest is not None
        assert rust_manifest.group(1) == request_set["deployment_profile"][
            "full_bundle_manifest_sha256"
        ]
        assert request_set["status"] == "CANARY_REQUEST_READY_FOR_KEYLESS_GENESIS_OPERATOR"
        assert verification["status"] == "CANARY_DEPLOY_REQUEST_VERIFIED"
        assert request_set["request_count"] == 1
        assert request_set["deployment_profile"]["selected_contracts"] == ["ValidatorStakingH001"]
        assert "metrics_oracle_pubkey" not in request_set
        assert "metrics_oracle_pubkey" not in request

        run(
            "scripts/build_silverc_deploy_operator_procedure.py",
            "--archive",
            archive,
            "--request-set",
            str(canary_set),
            "--requests-dir",
            str(canary_requests),
            "--summary-out",
            str(canary_procedure),
        )
        procedure = load(canary_procedure)
        assert procedure["status"] == "CANARY_READY_FOR_KEYLESS_GENESIS_OPERATION"
        assert procedure["request_count"] == 1
        assert procedure["required_public_result_fields"]["release_bundle.fixture_count"] == 7
        assert procedure["blockers"]

        results = {
            "schema_version": 1,
            "result_type": "prometheus_silverc_external_deploy_results",
            "network": "testnet",
            "deployment_profile": request_set["deployment_profile"],
            "provenance": {
                "type": "operator_record",
                "orchestrator": "canary-regression-test",
                "recorded_at": "2026-07-15T12:00:00Z",
            },
            "release_bundle": {
                "silverscript_ref": request_set["silverscript_ref"],
                "silverscript_commit": request_set["silverscript_commit"],
                "fixture_count": 7,
            },
            "request_set_sha256": request_set["request_set_sha256"],
            "results": [
                {
                    "status": "confirmed",
                    "contract_name": "ValidatorStakingH001",
                    "request_sha256": request["request_sha256"],
                    "deployed_instance_id": "22" * 32 + ":0",
                    "deploy_tx_id": "22" * 32,
                    "block_hash": "33" * 32,
                    "deployer_address": DEPLOYER,
                    "confirmations": 3,
                    "block_daa_score": 517_537_341,
                    "deployed_at": "2026-07-15T12:00:00Z",
                }
            ],
        }
        results_path = root / "canary-results.json"
        receipts_path = root / "canary-receipts.json"
        receipt_import = root / "canary-receipt-import.json"
        receipt_verification = root / "canary-receipt-verification.json"
        write(results_path, results)
        run(
            "scripts/build_silverc_operator_receipts.py",
            "--archive",
            archive,
            "--request-set",
            str(canary_set),
            "--requests-dir",
            str(canary_requests),
            "--orchestrator-results",
            str(results_path),
            "--operator-receipts-out",
            str(receipts_path),
            "--summary-out",
            str(receipt_import),
        )
        run(
            "scripts/verify_silverc_deploy_receipts.py",
            "--archive",
            archive,
            "--receipts",
            str(receipts_path),
            "--require-operator-record",
            "--summary-out",
            str(receipt_verification),
        )
        receipts = load(receipts_path)
        receipt_summary = load(receipt_verification)
        assert load(receipt_import)["status"] == "CANARY_OPERATOR_RECEIPTS_VERIFIED"
        assert receipt_summary["status"] == "CANARY_RECEIPTS_VERIFIED"
        assert receipt_summary["receipt_count"] == 1

        receipt = receipts["receipts"][0]
        evidence = {
            "schema_version": 1,
            "evidence_type": "prometheus_silverc_deploy_receipt_public_evidence",
            "network": "testnet",
            "deployment_profile": receipts["deployment_profile"],
            "provenance": {
                "type": "public_node_snapshot",
                "observer": "canary-regression-test",
                "observed_at": "2026-07-15T12:05:00Z",
            },
            "release_bundle": receipts["release_bundle"],
            "receipts_sha256": receipt_summary["receipts_sha256"],
            "receipt_count": 1,
            "observations": [
                {
                    "status": "confirmed",
                    "contract_name": receipt["contract_name"],
                    "deployed_instance_id": receipt["deployed_instance_id"],
                    "deploy_tx_id": receipt["deploy_tx_id"],
                    "block_hash": receipt["block_hash"],
                    "block_daa_score": receipt["block_daa_score"],
                    "confirmations": 4,
                    "explorer_url": "https://example.invalid/tx/" + receipt["deploy_tx_id"],
                }
            ],
        }
        evidence_path = root / "canary-evidence.json"
        evidence_summary = root / "canary-evidence-verification.json"
        status_draft = root / "canary-status-draft.json"
        write(evidence_path, evidence)
        run(
            "scripts/verify_silverc_deploy_receipt_evidence.py",
            "--archive",
            archive,
            "--receipts",
            str(receipts_path),
            "--evidence",
            str(evidence_path),
            "--summary-out",
            str(evidence_summary),
        )
        run(
            "scripts/stage_silverc_deployment_status.py",
            "--archive",
            archive,
            "--operator-receipts",
            str(receipts_path),
            "--status-out",
            str(status_draft),
        )
        assert load(evidence_summary)["status"] == "PUBLIC_CANARY_DEPLOY_EVIDENCE_VERIFIED"
        assert load(status_draft)["status"] == "READY_FOR_MANUAL_CANARY_STATUS_UPDATE"

        full_requests = root / "full-requests"
        full_set = root / "full-request-set.json"
        run(
            "scripts/build_silverc_deploy_requests.py",
            "--archive",
            archive,
            "--out-dir",
            str(full_requests),
            "--network",
            "testnet",
            "--rpc-url",
            RESOLVER,
            "--deployer-address",
            DEPLOYER,
            "--metrics-oracle-pubkey",
            ORACLE_KEY,
            "--request-set-out",
            str(full_set),
        )
        assert load(full_set)["request_count"] == 7

        missing_oracle = run(
            "scripts/build_silverc_deploy_requests.py",
            "--archive",
            archive,
            "--out-dir",
            str(root / "bad-full"),
            "--network",
            "testnet",
            "--rpc-url",
            RESOLVER,
            "--deployer-address",
            DEPLOYER,
            expect_success=False,
        )
        assert "required for --deployment-profile full" in missing_oracle.stderr

        canary_with_oracle = run(
            "scripts/build_silverc_deploy_requests.py",
            "--archive",
            archive,
            "--deployment-profile",
            CANARY_PROFILE,
            "--out-dir",
            str(root / "bad-canary-oracle"),
            "--network",
            "testnet",
            "--rpc-url",
            RESOLVER,
            "--deployer-address",
            DEPLOYER,
            "--metrics-oracle-pubkey",
            ORACLE_KEY,
            expect_success=False,
        )
        assert "forbidden for the H-001 canary" in canary_with_oracle.stderr

        canary_mainnet = run(
            "scripts/build_silverc_deploy_requests.py",
            "--archive",
            archive,
            "--deployment-profile",
            CANARY_PROFILE,
            "--out-dir",
            str(root / "bad-canary-mainnet"),
            "--network",
            "mainnet",
            "--rpc-url",
            "wss://mainnet.example.invalid",
            "--deployer-address",
            "kaspa:qptestpreflight0000000000000000000000000000000000",
            expect_success=False,
        )
        assert "restricted to --network testnet" in canary_mainnet.stderr

        tampered_profile = load(canary_set)
        tampered_profile["deployment_profile"]["selected_contracts"] = ["ValidatorStakingState"]
        rehash(tampered_profile, "request_set_sha256")
        tampered_profile_path = root / "tampered-canary-profile.json"
        write(tampered_profile_path, tampered_profile)
        profile_tamper = run(
            "scripts/verify_silverc_deploy_requests.py",
            "--archive",
            archive,
            "--request-set",
            str(tampered_profile_path),
            "--requests-dir",
            str(canary_requests),
            expect_success=False,
        )
        assert "profile or release-manifest binding mismatch" in profile_tamper.stderr

        unscoped_receipts = dict(receipts)
        unscoped_receipts.pop("deployment_profile")
        unscoped_path = root / "unscoped-canary-receipts.json"
        write(unscoped_path, unscoped_receipts)
        unscoped = run(
            "scripts/verify_silverc_deploy_receipts.py",
            "--archive",
            archive,
            "--receipts",
            str(unscoped_path),
            expect_success=False,
        )
        assert "expected one receipt per manifest contract" in unscoped.stderr

    print("H-001 canary deployment-profile regression: passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(parse_args()))
