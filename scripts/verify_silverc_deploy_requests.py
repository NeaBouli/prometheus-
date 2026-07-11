#!/usr/bin/env python3
"""Verify public Silverc deploy requests against a release bundle."""

from __future__ import annotations

import argparse
import json
import re
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any

from preflight_silverc_deploy import bundle_root_from_args, load_json, validate_manifest
from smoke_silverc_artifacts import FIXTURES, canonical_json_bytes
from verify_silverc_h001 import DEFAULT_SILVERSCRIPT_REF

REQUEST_SET_STATUS = "REQUESTS_READY_EXTERNAL_ORCHESTRATOR_REQUIRED"
REQUEST_STATUS = "READY_FOR_EXTERNAL_DEPLOY_ORCHESTRATOR"
REQUEST_TYPE = "prometheus_silverc_deploy_request"
SECRET_LIKE_RE = re.compile(r"(private|secret|seed|mnemonic|password|passwd|wallet|keystore|token)", re.IGNORECASE)
ALLOWED_SECRET_WORD_KEYS = {"accepts_private_keys"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify deterministic public Silverc deploy requests against a Prometheus "
            "release bundle. This checks request integrity only; it does not sign, "
            "assemble chain transactions, broadcast, deploy, or update status files."
        )
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--bundle-dir", type=Path, help="Directory containing manifest.json and artifacts")
    source.add_argument("--archive", type=Path, help="Release .tar.gz archive to validate")
    parser.add_argument("--request-set", type=Path, required=True, help="Request-set summary JSON")
    parser.add_argument("--requests-dir", type=Path, required=True, help="Directory containing deploy-request JSON files")
    parser.add_argument(
        "--silverscript-ref",
        default=DEFAULT_SILVERSCRIPT_REF,
        help="Expected Silverscript commit, tag, or branch in the release manifest",
    )
    parser.add_argument("--summary-out", type=Path, help="Optional JSON verification summary path")
    parser.add_argument("--runbook-out", type=Path, help="Optional Markdown verification runbook path")
    return parser.parse_args()


def reject_secret_fields(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            if key_text not in ALLOWED_SECRET_WORD_KEYS and SECRET_LIKE_RE.search(key_text):
                raise ValueError(f"{path}.{key}: secret-like fields are not allowed in deploy requests")
            reject_secret_fields(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_secret_fields(item, f"{path}[{index}]")


def require_dict(value: Any, key: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{key}: expected object")
    return value


def require_list(value: Any, key: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{key}: expected list")
    return value


def require_str(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key}: expected non-empty string")
    return value


def require_int(data: dict[str, Any], key: str) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{key}: expected integer")
    return value


def require_false_flags(data: dict[str, Any], path: str) -> None:
    expected = {
        "accepts_private_keys",
        "signs_transactions",
        "assembles_chain_transaction",
        "broadcasts_transactions",
        "deploys_contracts",
        "updates_status_files",
    }
    actual = set(data)
    missing = expected - actual
    extra = actual - expected
    if missing:
        raise ValueError(f"{path}: missing safety flags {sorted(missing)}")
    if extra:
        raise ValueError(f"{path}: unexpected safety flags {sorted(extra)}")
    for key in expected:
        if data[key] is not False:
            raise ValueError(f"{path}.{key}: expected false")


def hash_without_key(data: dict[str, Any], key: str) -> str:
    clone = dict(data)
    clone.pop(key, None)
    return sha256(canonical_json_bytes(clone)).hexdigest()


def fixture_args_by_contract() -> dict[str, Any]:
    return {fixture.contract_name: fixture.args for fixture in FIXTURES}


def validate_request_set_hash(request_set: dict[str, Any]) -> None:
    expected = require_str(request_set, "request_set_sha256")
    actual = hash_without_key(request_set, "request_set_sha256")
    if expected != actual:
        raise ValueError("request_set_sha256 mismatch")


def validate_request_hash(request: dict[str, Any], path: Path) -> None:
    expected = require_str(request, "request_sha256")
    actual = hash_without_key(request, "request_sha256")
    if expected != actual:
        raise ValueError(f"{path.name}: request_sha256 mismatch")


def validate_contract_payload(
    *,
    path: Path,
    contract: dict[str, Any],
    manifest_entry: dict[str, Any],
    order: int,
) -> None:
    if require_int(contract, "order") != order:
        raise ValueError(f"{path.name}: contract.order mismatch")
    checks = (
        "contract_name",
        "source_file",
        "artifact_file",
        "compiler_version",
        "script_len",
        "source_sha256",
        "constructor_args_sha256",
        "artifact_sha256",
        "script_sha256",
    )
    request_keys = {
        "contract_name": "name",
        "source_file": "source_file",
        "artifact_file": "artifact_file",
        "compiler_version": "compiler_version",
        "script_len": "script_len",
        "source_sha256": "source_sha256",
        "constructor_args_sha256": "constructor_args_sha256",
        "artifact_sha256": "artifact_sha256",
        "script_sha256": "script_sha256",
    }
    for manifest_key in checks:
        request_key = request_keys[manifest_key]
        if contract.get(request_key) != manifest_entry[manifest_key]:
            raise ValueError(f"{path.name}: contract.{request_key} manifest mismatch")
    if contract.get("abi") != manifest_entry["abi"]:
        raise ValueError(f"{path.name}: contract.abi manifest mismatch")
    if contract.get("state_layout") != manifest_entry["state_layout"]:
        raise ValueError(f"{path.name}: contract.state_layout manifest mismatch")


def validate_request_file(
    *,
    path: Path,
    request: dict[str, Any],
    request_set: dict[str, Any],
    request_entry: dict[str, Any],
    manifest_entry: dict[str, Any],
    constructor_args: Any,
    order: int,
) -> dict[str, Any]:
    reject_secret_fields(request)
    validate_request_hash(request, path)

    if request.get("schema_version") != 1:
        raise ValueError(f"{path.name}: schema_version expected 1")
    if request.get("request_type") != REQUEST_TYPE:
        raise ValueError(f"{path.name}: request_type mismatch")
    if request.get("status") != REQUEST_STATUS:
        raise ValueError(f"{path.name}: status mismatch")
    for key in ("network", "rpc_url", "deployer_address", "metrics_oracle_pubkey"):
        if request.get(key) != request_set[key]:
            raise ValueError(f"{path.name}: {key} mismatch")

    silverscript = require_dict(request.get("silverscript"), f"{path.name}.silverscript")
    if silverscript.get("ref") != request_set["silverscript_ref"]:
        raise ValueError(f"{path.name}: silverscript.ref mismatch")
    if silverscript.get("commit") != request_set["silverscript_commit"]:
        raise ValueError(f"{path.name}: silverscript.commit mismatch")

    contract = require_dict(request.get("contract"), f"{path.name}.contract")
    validate_contract_payload(path=path, contract=contract, manifest_entry=manifest_entry, order=order)
    if request.get("constructor_args") != constructor_args:
        raise ValueError(f"{path.name}: constructor_args mismatch")
    if request_entry.get("contract_name") != manifest_entry["contract_name"]:
        raise ValueError(f"{path.name}: request-set contract_name mismatch")
    if request_entry.get("request_sha256") != request["request_sha256"]:
        raise ValueError(f"{path.name}: request-set request_sha256 mismatch")
    if request_entry.get("artifact_sha256") != manifest_entry["artifact_sha256"]:
        raise ValueError(f"{path.name}: request-set artifact_sha256 mismatch")
    if request_entry.get("script_sha256") != manifest_entry["script_sha256"]:
        raise ValueError(f"{path.name}: request-set script_sha256 mismatch")

    require_false_flags(require_dict(request.get("safety"), f"{path.name}.safety"), f"{path.name}.safety")

    return {
        "order": order,
        "contract_name": manifest_entry["contract_name"],
        "file": path.name,
        "request_sha256": request["request_sha256"],
        "artifact_sha256": manifest_entry["artifact_sha256"],
        "script_sha256": manifest_entry["script_sha256"],
    }


def validate_request_set(
    *,
    request_set: dict[str, Any],
    requests_dir: Path,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    reject_secret_fields(request_set)
    validate_request_set_hash(request_set)

    if request_set.get("schema_version") != 1:
        raise ValueError("schema_version: expected 1")
    if request_set.get("status") != REQUEST_SET_STATUS:
        raise ValueError("status: expected REQUESTS_READY_EXTERNAL_ORCHESTRATOR_REQUIRED")
    if request_set.get("silverscript_ref") != manifest["silverscript_ref"]:
        raise ValueError("silverscript_ref mismatch")
    if request_set.get("silverscript_commit") != manifest["silverscript_commit"]:
        raise ValueError("silverscript_commit mismatch")
    if request_set.get("request_count") != manifest["fixture_count"]:
        raise ValueError("request_count mismatch")
    if "missing approved external deploy orchestrator implementation" not in request_set.get("blockers", []):
        raise ValueError("blockers: expected missing approved external deploy orchestrator implementation")
    require_false_flags(require_dict(request_set.get("safety"), "$.safety"), "$.safety")

    request_entries = require_list(request_set.get("requests"), "requests")
    manifest_entries = manifest["fixtures"]
    constructor_args = fixture_args_by_contract()
    if len(request_entries) != len(manifest_entries):
        raise ValueError("requests: expected one request per manifest contract")

    verified = []
    for index, (request_entry, manifest_entry) in enumerate(zip(request_entries, manifest_entries), start=1):
        if not isinstance(request_entry, dict):
            raise ValueError(f"requests[{index - 1}]: expected object")
        if request_entry.get("order") != index:
            raise ValueError(f"requests[{index - 1}].order mismatch")
        filename = require_str(request_entry, "file")
        expected_filename = f"{index:02d}-{manifest_entry['contract_name']}.deploy-request.json"
        if filename != expected_filename:
            raise ValueError(f"requests[{index - 1}].file mismatch")
        path = requests_dir / filename
        if not path.is_file():
            raise FileNotFoundError(f"missing deploy request file: {path}")
        request = load_json(path)
        verified.append(
            validate_request_file(
                path=path,
                request=request,
                request_set=request_set,
                request_entry=request_entry,
                manifest_entry=manifest_entry,
                constructor_args=constructor_args[manifest_entry["contract_name"]],
                order=index,
            )
        )

    return {
        "schema_version": 1,
        "status": "DEPLOY_REQUEST_SET_VERIFIED",
        "network": request_set["network"],
        "silverscript_commit": manifest["silverscript_commit"],
        "request_count": len(verified),
        "request_set_sha256": request_set["request_set_sha256"],
        "requests": verified,
        "blockers": ["approved external deploy orchestrator still required for signing and broadcast"],
        "safety": {
            "accepts_private_keys": False,
            "signs_transactions": False,
            "assembles_chain_transaction": False,
            "broadcasts_transactions": False,
            "deploys_contracts": False,
            "updates_status_files": False,
        },
    }


def write_json(path: Path | None, value: dict[str, Any]) -> None:
    if not path:
        return
    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_runbook(path: Path | None, summary: dict[str, Any]) -> None:
    if not path:
        return
    lines = [
        "# Prometheus Silverc Deploy Request Verification",
        "",
        f"Status: {summary['status']}",
        f"Network: {summary['network']}",
        f"Silverscript commit: `{summary['silverscript_commit']}`",
        f"Request set SHA-256: `{summary['request_set_sha256']}`",
        "",
        "## Safety Rules",
        "",
        "- This verifier accepts public deploy-request JSON only.",
        "- This verifier does not accept private keys, sign transactions, assemble chain transactions, broadcast, deploy, or update status files.",
        "- A verified request set is still blocked until an approved external deploy orchestrator signs and broadcasts outside this repository.",
        "",
        "## Requests",
        "",
        "| Order | Contract | File | Request SHA-256 | Script SHA-256 |",
        "|------:|----------|------|-----------------|----------------|",
    ]
    for request in summary["requests"]:
        lines.append(
            "| {order} | `{contract}` | `{file}` | `{request_hash}` | `{script_hash}` |".format(
                order=request["order"],
                contract=request["contract_name"],
                file=request["file"],
                request_hash=request["request_sha256"],
                script_hash=request["script_sha256"],
            )
        )
    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    bundle_dir, tmp = bundle_root_from_args(args)
    try:
        manifest = validate_manifest(bundle_dir, args.silverscript_ref)
        request_set = load_json(args.request_set.expanduser().resolve())
        requests_dir = args.requests_dir.expanduser().resolve()
        if not requests_dir.is_dir():
            raise FileNotFoundError(f"requests directory not found: {requests_dir}")
        summary = validate_request_set(request_set=request_set, requests_dir=requests_dir, manifest=manifest)
        write_json(args.summary_out, summary)
        write_runbook(args.runbook_out, summary)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    finally:
        if tmp is not None:
            tmp.cleanup()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
