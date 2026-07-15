#!/usr/bin/env python3
"""Validate a Prometheus Silverc release bundle before any network deploy attempt."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from smoke_silverc_artifacts import (
    ARCHIVE_MEMBER_PREFIX,
    FIXTURES,
    MANIFEST_NAME,
    ROOT,
    canonical_json_bytes,
    sha256_bytes,
    sha256_file,
)
from silverc_deployment_profiles import (
    DEPLOYMENT_PROFILES,
    FULL_PROFILE,
    H001_CANARY_PROFILE,
    PUBLIC_RESOLVER_URL,
    expected_profile,
)
from verify_silverc_h001 import (
    DEFAULT_SILVERSCRIPT_REF,
    DEFAULT_SILVERSCRIPT_REPO,
    ensure_silverscript_repo,
)

NETWORKS = ("sandbox", "testnet", "mainnet")
HEX_32_BYTES_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")
KASPA_ADDRESS_RE = re.compile(r"^(kaspa|kaspatest|kaspadev):[a-z0-9]{20,}$")
SECRET_LIKE_RE = re.compile(
    r"(private|secret|seed|mnemonic|password|passwd|wallet|keystore|token)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ToolingStatus:
    silverc_path: str
    has_deploy_command: bool
    repository_operator_manifest: str
    has_repository_genesis_operator: bool
    help_excerpt: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Preflight-check a Prometheus current-Silverc release bundle. "
            "The script validates artifacts, public inputs, and available deploy tooling; "
            "it does not deploy."
        )
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--bundle-dir", type=Path, help="Directory containing manifest.json and artifacts")
    source.add_argument("--archive", type=Path, help="Release .tar.gz archive to validate")
    parser.add_argument(
        "--deployment-profile",
        choices=DEPLOYMENT_PROFILES,
        default=FULL_PROFILE,
        help="Closed deployment scope; the H-001 canary cannot authorize a full rollout",
    )
    parser.add_argument("--network", choices=NETWORKS, default="sandbox")
    parser.add_argument("--rpc-url", help="Public Kaspa RPC/wRPC endpoint intended for deployment")
    parser.add_argument("--deployer-address", help="Public deployer address; never pass private keys")
    parser.add_argument(
        "--metrics-oracle-pubkey",
        help="32-byte x-only metrics-oracle public key as hex; never pass private keys",
    )
    parser.add_argument(
        "--silverscript-repo",
        default=os.environ.get("SILVERSCRIPT_REPO", str(DEFAULT_SILVERSCRIPT_REPO)),
        help="Path to a local kaspanet/silverscript checkout for silverc capability inspection",
    )
    parser.add_argument(
        "--silverscript-ref",
        default=os.environ.get("SILVERSCRIPT_REF", DEFAULT_SILVERSCRIPT_REF),
        help="Silverscript commit, tag, or branch to inspect before deployment",
    )
    parser.add_argument("--plan-out", type=Path, help="Optional JSON deployment preflight report path")
    parser.add_argument("--runbook-out", type=Path, help="Optional Markdown operator handoff runbook path")
    parser.add_argument(
        "--require-network-deploy-tool",
        action="store_true",
        help="Fail unless upstream silverc or the repository genesis operator provides a deploy path",
    )
    return parser.parse_args()


def run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    if proc.returncode != 0:
        if proc.stdout:
            print(proc.stdout, file=sys.stdout)
        if proc.stderr:
            print(proc.stderr, file=sys.stderr)
        proc.check_returncode()
    return proc


def safe_extract_archive(archive: Path, destination: Path) -> Path:
    archive = archive.expanduser().resolve()
    if not archive.is_file():
        raise FileNotFoundError(f"release archive not found: {archive}")

    root = destination / ARCHIVE_MEMBER_PREFIX
    with tarfile.open(archive, "r:gz") as tar:
        members = []
        for member in tar.getmembers():
            path = Path(member.name)
            if member.isdir():
                continue
            if member.issym() or member.islnk() or not member.isfile():
                raise ValueError(f"{archive}: unsupported archive member type: {member.name}")
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"{archive}: unsafe archive member path: {member.name}")
            if len(path.parts) != 2 or path.parts[0] != ARCHIVE_MEMBER_PREFIX:
                raise ValueError(f"{archive}: unexpected archive member path: {member.name}")
            if path.suffix != ".json":
                raise ValueError(f"{archive}: unexpected non-json archive member: {member.name}")
            members.append(member)
        tar.extractall(destination, members=members)

    if not (root / MANIFEST_NAME).is_file():
        raise FileNotFoundError(f"{archive}: missing {ARCHIVE_MEMBER_PREFIX}/{MANIFEST_NAME}")
    return root


def bundle_root_from_args(args: argparse.Namespace) -> tuple[Path, tempfile.TemporaryDirectory[str] | None]:
    if args.bundle_dir:
        bundle_dir = args.bundle_dir.expanduser().resolve()
        if not bundle_dir.is_dir():
            raise FileNotFoundError(f"bundle directory not found: {bundle_dir}")
        return bundle_dir, None

    tmp = tempfile.TemporaryDirectory(prefix="prometheus-silverc-preflight.")
    return safe_extract_archive(args.archive, Path(tmp.name)), tmp


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected JSON object")
    return data


def validate_manifest(bundle_dir: Path, expected_silverscript_ref: str) -> dict[str, Any]:
    manifest_path = bundle_dir / MANIFEST_NAME
    manifest = load_json(manifest_path)
    fixtures = manifest.get("fixtures")
    expected_names = [fixture.contract_name for fixture in FIXTURES]
    fixtures_by_name = {fixture.contract_name: fixture for fixture in FIXTURES}

    if manifest.get("schema_version") != 1:
        raise ValueError(f"{manifest_path}: unsupported schema_version")
    if manifest.get("fixture_count") != len(FIXTURES):
        raise ValueError(f"{manifest_path}: fixture_count mismatch")
    if not isinstance(fixtures, list) or len(fixtures) != len(FIXTURES):
        raise ValueError(f"{manifest_path}: fixtures list mismatch")
    actual_names = [entry.get("contract_name") for entry in fixtures]
    if actual_names != expected_names:
        raise ValueError(f"{manifest_path}: fixture order/name mismatch")
    if manifest.get("silverscript_ref") != expected_silverscript_ref:
        raise ValueError(f"{manifest_path}: unexpected silverscript_ref")

    for entry in fixtures:
        fixture = fixtures_by_name[entry["contract_name"]]
        validate_manifest_entry(bundle_dir, entry, fixture)

    return manifest


def validate_manifest_entry(bundle_dir: Path, entry: dict[str, Any], fixture: Any) -> None:
    artifact_name = entry.get("artifact_file")
    if not isinstance(artifact_name, str) or "/" in artifact_name:
        raise ValueError(f"{MANIFEST_NAME}: invalid artifact_file for {entry.get('contract_name')}")
    artifact = bundle_dir / artifact_name
    if not artifact.is_file():
        raise FileNotFoundError(f"{MANIFEST_NAME}: missing artifact {artifact_name}")
    if entry.get("artifact_sha256") != sha256_file(artifact):
        raise ValueError(f"{MANIFEST_NAME}: artifact hash mismatch for {artifact_name}")
    if entry.get("constructor_args_sha256") != sha256_bytes(canonical_json_bytes(fixture.args)):
        raise ValueError(f"{MANIFEST_NAME}: constructor args hash mismatch for {artifact_name}")

    source_file = entry.get("source_file")
    if not isinstance(source_file, str):
        raise ValueError(f"{MANIFEST_NAME}: invalid source_file for {entry.get('contract_name')}")
    source = ROOT / source_file
    if not source.is_file():
        raise FileNotFoundError(f"{MANIFEST_NAME}: missing source file {source_file}")
    if entry.get("source_sha256") != sha256_file(source):
        raise ValueError(f"{MANIFEST_NAME}: source hash mismatch for {source_file}")

    artifact_data = load_json(artifact)
    script = artifact_data.get("script")
    if not isinstance(script, list) or not script:
        raise ValueError(f"{artifact}: missing compiled script bytes")
    if not all(isinstance(byte, int) and 0 <= byte <= 255 for byte in script):
        raise ValueError(f"{artifact}: script contains non-byte values")
    if entry.get("script_sha256") != sha256_bytes(bytes(script)):
        raise ValueError(f"{MANIFEST_NAME}: script hash mismatch for {artifact_name}")
    if entry.get("script_len") != len(script):
        raise ValueError(f"{MANIFEST_NAME}: script length mismatch for {artifact_name}")
    if not isinstance(entry.get("abi"), list) or not entry["abi"]:
        raise ValueError(f"{MANIFEST_NAME}: missing ABI entries for {artifact_name}")
    if not isinstance(entry.get("state_layout"), dict):
        raise ValueError(f"{MANIFEST_NAME}: missing state_layout for {artifact_name}")
    if not entry.get("compiler_version"):
        raise ValueError(f"{MANIFEST_NAME}: missing compiler_version for {artifact_name}")


def validate_operator_inputs(args: argparse.Namespace) -> list[str]:
    missing = []
    if not args.rpc_url:
        missing.append("rpc_url")
    if not args.deployer_address:
        missing.append("deployer_address")
    if args.deployment_profile == FULL_PROFILE and not args.metrics_oracle_pubkey:
        missing.append("metrics_oracle_pubkey")

    if args.rpc_url:
        validate_deploy_rpc_url(args.rpc_url, args.network)
    if args.deployer_address and not KASPA_ADDRESS_RE.match(args.deployer_address):
        raise ValueError("--deployer-address must be a public Kaspa address")
    if args.metrics_oracle_pubkey and not HEX_32_BYTES_RE.match(args.metrics_oracle_pubkey):
        raise ValueError("--metrics-oracle-pubkey must be a 32-byte public key hex string")
    if args.deployment_profile == H001_CANARY_PROFILE:
        if args.network != "testnet":
            raise ValueError("the H-001 canary deployment profile is restricted to --network testnet")
        if args.rpc_url and args.rpc_url != PUBLIC_RESOLVER_URL:
            raise ValueError(
                "the H-001 canary deployment profile requires --rpc-url kaspa-resolver://public"
            )
        if args.metrics_oracle_pubkey is not None:
            raise ValueError(
                "--metrics-oracle-pubkey is forbidden for the H-001 canary deployment profile"
            )
    return missing


def validate_deploy_rpc_url(rpc_url: str, network: str) -> None:
    if not isinstance(rpc_url, str) or not rpc_url:
        raise ValueError("--rpc-url must be a non-empty string")
    if rpc_url == PUBLIC_RESOLVER_URL:
        if network != "testnet":
            raise ValueError("--rpc-url public resolver is restricted to --network testnet")
        return

    parsed = urlparse(rpc_url)
    if parsed.scheme not in {"ws", "wss"}:
        raise ValueError("--rpc-url must use ws:// or wss://")
    if parsed.username or parsed.password:
        raise ValueError("--rpc-url must not contain credentials")
    if not parsed.hostname:
        raise ValueError("--rpc-url must include a host")
    if parsed.query or parsed.fragment:
        raise ValueError("--rpc-url must not contain query strings or fragments")
    if SECRET_LIKE_RE.search(rpc_url):
        raise ValueError("--rpc-url contains secret-like text")


def inspect_silverc(silverscript_repo: Path, silverscript_ref: str) -> ToolingStatus:
    ensure_silverscript_repo(silverscript_repo, silverscript_ref)
    silverc = silverscript_repo / "target" / "debug" / "silverc"
    if not silverc.exists():
        run(["cargo", "build", "-p", "silverscript-lang", "--bin", "silverc"], silverscript_repo)
    if not silverc.exists():
        raise FileNotFoundError(f"silverc binary was not built: {silverc}")

    help_text = run([str(silverc), "--help"], ROOT).stdout
    deploy_tokens = {"deploy", "publish", "broadcast", "submit"}
    commands = {token.strip(" ,;:.").lower() for token in help_text.split()}
    has_deploy = bool(deploy_tokens & commands)
    operator_manifest = ROOT / "modules" / "silverc-deployer" / "Cargo.toml"
    has_repository_operator = False
    if operator_manifest.is_file():
        manifest = tomllib.loads(operator_manifest.read_text(encoding="utf-8"))
        metadata = json.loads(
            run(["cargo", "metadata", "--no-deps", "--format-version", "1"], ROOT).stdout
        )
        package = next(
            (
                item
                for item in metadata.get("packages", [])
                if item.get("name") == "prometheus-silverc-deployer"
            ),
            None,
        )
        targets = package.get("targets", []) if package else []
        has_repository_operator = (
            manifest.get("package", {}).get("name") == "prometheus-silverc-deployer"
            and any(
                target.get("name") == "prometheus-silverc-deployer"
                and "bin" in target.get("kind", [])
                for target in targets
            )
        )
    return ToolingStatus(
        silverc_path=str(silverc),
        has_deploy_command=has_deploy,
        repository_operator_manifest=str(operator_manifest),
        has_repository_genesis_operator=has_repository_operator,
        help_excerpt="\n".join(help_text.splitlines()[:20]),
    )


def write_plan(
    args: argparse.Namespace,
    manifest: dict[str, Any],
    missing_inputs: list[str],
    tooling: ToolingStatus,
) -> dict[str, Any]:
    deployment_profile = expected_profile(args.deployment_profile, manifest)
    plan = {
        "schema_version": 1,
        "network": args.network,
        "deployment_profile": deployment_profile,
        "bundle": {
            "silverscript_ref": manifest["silverscript_ref"],
            "silverscript_commit": manifest["silverscript_commit"],
            "fixture_count": manifest["fixture_count"],
            "contracts": [entry["contract_name"] for entry in manifest["fixtures"]],
        },
        "operator_inputs": {
            "rpc_url_present": bool(args.rpc_url),
            "deployer_address_present": bool(args.deployer_address),
            "metrics_oracle_pubkey_present": bool(args.metrics_oracle_pubkey),
            "missing": missing_inputs,
        },
        "tooling": {
            "silverc_path": tooling.silverc_path,
            "upstream_silverc_has_network_deploy_command": tooling.has_deploy_command,
            "repository_operator_manifest": tooling.repository_operator_manifest,
            "has_repository_toccata_v1_genesis_operator": tooling.has_repository_genesis_operator,
        },
        "deploy_supported": (
            tooling.has_deploy_command or tooling.has_repository_genesis_operator
        )
        and not missing_inputs,
        "deploy_blockers": [],
    }
    if missing_inputs:
        plan["deploy_blockers"].append("missing public operator inputs: " + ", ".join(missing_inputs))
    if not tooling.has_deploy_command and not tooling.has_repository_genesis_operator:
        plan["deploy_blockers"].append(
            "no upstream or repository network deploy operator is available"
        )

    if args.plan_out:
        plan_path = args.plan_out.expanduser().resolve()
        plan_path.parent.mkdir(parents=True, exist_ok=True)
        plan_path.write_text(
            json.dumps(plan, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return plan


def write_runbook(args: argparse.Namespace, manifest: dict[str, Any], plan: dict[str, Any]) -> None:
    if not args.runbook_out:
        return

    if not plan["deploy_supported"]:
        status = "BLOCKED"
    elif plan["deployment_profile"]["kind"] == "canary":
        status = "CANARY_READY_FOR_NETWORK_DEPLOY_TOOL"
    else:
        status = "READY_FOR_NETWORK_DEPLOY_TOOL"
    lines = [
        "# Prometheus Silverc Deploy Preflight Runbook",
        "",
        f"Status: {status}",
        f"Network: {plan['network']}",
        f"Deployment profile: `{plan['deployment_profile']['name']}`",
        f"Silverscript ref: `{plan['bundle']['silverscript_ref']}`",
        f"Silverscript commit: `{plan['bundle']['silverscript_commit']}`",
        f"Fixture count: {plan['bundle']['fixture_count']}",
        "",
        "## Safety Rules",
        "",
        "- This runbook is generated from a validated release bundle.",
        "- This preflight does not deploy or broadcast transactions.",
        "- Do not paste private keys, seed phrases, wallet files, or keystore material into this repo or into preflight arguments.",
        "- Operator secrets must stay in the local wallet/keychain or deployment vault.",
        "- Validators stake KAS only; PROM remains earned-only and is not a staking asset.",
        "",
        "## Public Operator Inputs",
        "",
        f"- RPC URL present: {str(plan['operator_inputs']['rpc_url_present']).lower()}",
        f"- Deployer address present: {str(plan['operator_inputs']['deployer_address_present']).lower()}",
        f"- Metrics-oracle public key present: {str(plan['operator_inputs']['metrics_oracle_pubkey_present']).lower()}",
        f"- Missing public inputs: {', '.join(plan['operator_inputs']['missing']) or 'none'}",
        "",
        "## Tooling",
        "",
        f"- silverc path inspected: `{plan['tooling']['silverc_path']}`",
        f"- Upstream silverc network deploy command: {str(plan['tooling']['upstream_silverc_has_network_deploy_command']).lower()}",
        f"- Repository Toccata-v1 genesis operator: {str(plan['tooling']['has_repository_toccata_v1_genesis_operator']).lower()}",
        f"- Repository operator manifest: `{plan['tooling']['repository_operator_manifest']}`",
        "",
        "## Contracts",
        "",
        "| Order | Contract | Artifact | Script SHA-256 | Script bytes |",
        "|------:|----------|----------|----------------|-------------:|",
    ]
    selected_contracts = set(plan["deployment_profile"]["selected_contracts"])
    for index, entry in enumerate(manifest["fixtures"], start=1):
        if entry["contract_name"] not in selected_contracts:
            continue
        lines.append(
            "| {index} | `{contract}` | `{artifact}` | `{script_hash}` | {script_len} |".format(
                index=index,
                contract=entry["contract_name"],
                artifact=entry["artifact_file"],
                script_hash=entry["script_sha256"],
                script_len=entry["script_len"],
            )
        )

    lines.extend(
        [
            "",
            "## Operator Sequence",
            "",
            "1. Build the release archive with `scripts/smoke_silverc_artifacts.py --archive <path>`.",
            "2. Run this preflight against the archive with public RPC/deployer/oracle inputs only.",
            "3. Confirm every source, constructor-args, artifact, and script hash is covered by the generated manifest.",
            "4. Follow `docs/runbooks/silverc-genesis-operator.md` and run the live Toccata node preflight.",
            "5. Use a separate vault/HSM process for signing the public digest; never store signing material in the repository.",
            "6. Record deployed contract IDs/addresses in `memory/STATUS.md` only after a real network receipt is verified.",
            "",
            "## Deploy Blockers",
            "",
        ]
    )
    blockers = plan["deploy_blockers"]
    if blockers:
        lines.extend(f"- {blocker}" for blocker in blockers)
    else:
        lines.append("- none")

    runbook_path = args.runbook_out.expanduser().resolve()
    runbook_path.parent.mkdir(parents=True, exist_ok=True)
    runbook_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    silverscript_repo = Path(args.silverscript_repo).expanduser().resolve()
    bundle_dir, tmp = bundle_root_from_args(args)
    try:
        manifest = validate_manifest(bundle_dir, args.silverscript_ref)
        missing_inputs = validate_operator_inputs(args)
        tooling = inspect_silverc(silverscript_repo, args.silverscript_ref)
        plan = write_plan(args, manifest, missing_inputs, tooling)
        write_runbook(args, manifest, plan)
        print(json.dumps(plan, indent=2, sort_keys=True))

        if args.require_network_deploy_tool and not plan["deploy_supported"]:
            raise RuntimeError("required network deploy tool is unavailable")
        return 0
    finally:
        if tmp is not None:
            tmp.cleanup()


if __name__ == "__main__":
    sys.exit(main())
