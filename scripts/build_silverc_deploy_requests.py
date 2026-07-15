#!/usr/bin/env python3
"""Build public Silverc deploy requests for the keyless genesis operator."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from preflight_silverc_deploy import (
    HEX_32_BYTES_RE,
    KASPA_ADDRESS_RE,
    NETWORKS,
    bundle_root_from_args,
    load_json,
    validate_manifest,
)
from smoke_silverc_artifacts import FIXTURES, canonical_json_bytes
from verify_silverc_h001 import DEFAULT_SILVERSCRIPT_REF

DEFAULT_OUT_DIR = Path("/tmp/prometheus-silverc-deploy-requests")
SECRET_LIKE_RE = re.compile(r"(private|secret|seed|mnemonic|password|passwd|wallet|keystore|token)", re.IGNORECASE)
REQUEST_BLOCKER = (
    "real funded UTXO, external Schnorr signer response, and public chain evidence are required before repository broadcast"
)
REQUEST_SAFETY_SCOPE = "deploy_request_builder_only"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build deterministic public deploy-request JSON files from a Prometheus "
            "current-Silverc release bundle. The requests are for an external "
            "orchestrator only; this script does not sign, assemble chain "
            "transactions, broadcast, deploy, or update status files."
        )
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--bundle-dir", type=Path, help="Directory containing manifest.json and artifacts")
    source.add_argument("--archive", type=Path, help="Release .tar.gz archive to validate")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR, help="Directory for per-contract requests")
    parser.add_argument("--network", choices=NETWORKS, required=True)
    parser.add_argument("--rpc-url", required=True, help="Public Kaspa RPC/wRPC endpoint; credentials are rejected")
    parser.add_argument("--deployer-address", required=True, help="Public deployer address")
    parser.add_argument(
        "--metrics-oracle-pubkey",
        required=True,
        help="32-byte x-only metrics-oracle public key hex; never pass private keys",
    )
    parser.add_argument(
        "--silverscript-ref",
        default=DEFAULT_SILVERSCRIPT_REF,
        help="Expected Silverscript commit, tag, or branch in the release manifest",
    )
    parser.add_argument("--request-set-out", type=Path, help="Optional JSON request-set summary path")
    parser.add_argument("--runbook-out", type=Path, help="Optional Markdown deploy-request runbook path")
    return parser.parse_args()


def reject_secret_fields(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if SECRET_LIKE_RE.search(str(key)):
                raise ValueError(f"{path}.{key}: secret-like fields are not allowed in deploy requests")
            reject_secret_fields(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_secret_fields(item, f"{path}[{index}]")


def validate_public_inputs(args: argparse.Namespace) -> None:
    parsed = urlparse(args.rpc_url)
    if parsed.scheme not in {"ws", "wss", "http", "https"}:
        raise ValueError("--rpc-url must start with ws://, wss://, http://, or https://")
    if parsed.username or parsed.password:
        raise ValueError("--rpc-url must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("--rpc-url must not contain query strings or fragments")
    if SECRET_LIKE_RE.search(args.rpc_url):
        raise ValueError("--rpc-url contains secret-like text")
    if not KASPA_ADDRESS_RE.match(args.deployer_address):
        raise ValueError("--deployer-address must be a public Kaspa address")
    if not HEX_32_BYTES_RE.match(args.metrics_oracle_pubkey):
        raise ValueError("--metrics-oracle-pubkey must be a 32-byte public key hex string")


def fixture_args_by_contract() -> dict[str, Any]:
    return {fixture.contract_name: fixture.args for fixture in FIXTURES}


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def request_hash(request: dict[str, Any]) -> str:
    return sha256(canonical_json_bytes(request)).hexdigest()


def build_request(
    *,
    args: argparse.Namespace,
    manifest: dict[str, Any],
    entry: dict[str, Any],
    order: int,
    constructor_args: Any,
) -> dict[str, Any]:
    reject_secret_fields(constructor_args, "$.constructor_args")
    request = {
        "schema_version": 1,
        "request_type": "prometheus_silverc_deploy_request",
        "status": "READY_FOR_KEYLESS_GENESIS_OPERATOR",
        "network": args.network,
        "rpc_url": args.rpc_url,
        "deployer_address": args.deployer_address,
        "metrics_oracle_pubkey": args.metrics_oracle_pubkey,
        "silverscript": {
            "ref": manifest["silverscript_ref"],
            "commit": manifest["silverscript_commit"],
        },
        "contract": {
            "order": order,
            "name": entry["contract_name"],
            "source_file": entry["source_file"],
            "artifact_file": entry["artifact_file"],
            "compiler_version": entry["compiler_version"],
            "abi": entry["abi"],
            "state_layout": entry["state_layout"],
            "script_len": entry["script_len"],
            "source_sha256": entry["source_sha256"],
            "constructor_args_sha256": entry["constructor_args_sha256"],
            "artifact_sha256": entry["artifact_sha256"],
            "script_sha256": entry["script_sha256"],
        },
        "constructor_args": constructor_args,
        "orchestrator_requirements": [
            "Validate this request hash before signing or broadcasting.",
            "Use prometheus-silverc-deployer to assemble and verify the keyless transaction in memory.",
            "Send only the canonical 32-byte sighash to the approved external vault/HSM signer.",
            "Return the public signature response to prometheus-silverc-deployer for verification and broadcast.",
            "Return public operator_record receipts that match this request and the release-bundle manifest.",
            "Never copy private keys, seed phrases, wallet files, or keystore material into this repository.",
        ],
        "safety": {
            "accepts_private_keys": False,
            "signs_transactions": False,
            "assembles_chain_transaction": False,
            "broadcasts_transactions": False,
            "deploys_contracts": False,
            "updates_status_files": False,
        },
        "safety_scope": REQUEST_SAFETY_SCOPE,
    }
    request["request_sha256"] = request_hash(request)
    return request


def write_runbook(path: Path | None, summary: dict[str, Any]) -> None:
    if not path:
        return
    lines = [
        "# Prometheus Silverc Keyless Genesis Deploy Requests",
        "",
        f"Status: {summary['status']}",
        f"Network: {summary['network']}",
        f"Silverscript commit: `{summary['silverscript_commit']}`",
        f"Request set SHA-256: `{summary['request_set_sha256']}`",
        "",
        "## Safety Rules",
        "",
        "- These are public deploy requests for the repository keyless genesis operator.",
        "- These request-builder artifacts do not accept private keys, sign transactions, assemble chain transactions, broadcast, deploy, or update status files.",
        "- Operator secrets must remain in the approved wallet/vault process.",
        "- Real deployment status still requires verified `operator_record` receipts.",
        "",
        "## Requests",
        "",
        "| Order | Contract | Request file | Request SHA-256 | Script SHA-256 |",
        "|------:|----------|--------------|-----------------|----------------|",
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
    lines.extend(
        [
            "",
            "## Operator Sequence",
            "",
            "1. Build and verify the release archive.",
            "2. Build this deploy-request set with public RPC/deployer/oracle inputs only.",
            "3. Import each request into `prometheus-silverc-deployer` with public funding data.",
            "4. Verify every request SHA-256 before signing.",
            "5. Sign only the digest externally; verify and broadcast with the repository operator.",
            "6. Feed public `operator_record` receipts back into the receipt verifier and status staging guard.",
        ]
    )
    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    validate_public_inputs(args)
    bundle_dir, tmp = bundle_root_from_args(args)
    try:
        manifest = validate_manifest(bundle_dir, args.silverscript_ref)
        constructor_args = fixture_args_by_contract()
        out_dir = args.out_dir.expanduser().resolve()
        if out_dir.exists():
            shutil.rmtree(out_dir)
        out_dir.mkdir(parents=True)

        request_entries = []
        for order, entry in enumerate(manifest["fixtures"], start=1):
            contract_name = entry["contract_name"]
            if contract_name not in constructor_args:
                raise ValueError(f"{contract_name}: missing constructor args")
            request = build_request(
                args=args,
                manifest=manifest,
                entry=entry,
                order=order,
                constructor_args=constructor_args[contract_name],
            )
            filename = f"{order:02d}-{contract_name}.deploy-request.json"
            write_json(out_dir / filename, request)
            request_entries.append(
                {
                    "order": order,
                    "contract_name": contract_name,
                    "file": filename,
                    "request_sha256": request["request_sha256"],
                    "artifact_sha256": entry["artifact_sha256"],
                    "script_sha256": entry["script_sha256"],
                }
            )

        summary = {
            "schema_version": 1,
            "status": "REQUESTS_READY_FOR_KEYLESS_GENESIS_OPERATOR",
            "network": args.network,
            "rpc_url": args.rpc_url,
            "deployer_address": args.deployer_address,
            "metrics_oracle_pubkey": args.metrics_oracle_pubkey,
            "silverscript_ref": manifest["silverscript_ref"],
            "silverscript_commit": manifest["silverscript_commit"],
            "request_count": len(request_entries),
            "requests": request_entries,
            "blockers": [REQUEST_BLOCKER],
            "safety": {
                "accepts_private_keys": False,
                "signs_transactions": False,
                "assembles_chain_transaction": False,
                "broadcasts_transactions": False,
                "deploys_contracts": False,
                "updates_status_files": False,
            },
            "safety_scope": REQUEST_SAFETY_SCOPE,
        }
        summary["request_set_sha256"] = sha256(canonical_json_bytes(summary)).hexdigest()
        if args.request_set_out:
            write_json(args.request_set_out.expanduser().resolve(), summary)
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
