#!/usr/bin/env python3
"""Compile Prometheus current-silverc fixtures through the silverc CLI."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from verify_silverc_h001 import (
    DEFAULT_SILVERSCRIPT_REF,
    DEFAULT_SILVERSCRIPT_REPO,
    ensure_silverscript_repo,
)

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_DIR = ROOT / "modules" / "contracts" / "silverc"
DEFAULT_OUTPUT_DIR = Path("/tmp/prometheus-silverc-artifacts")
MANIFEST_NAME = "manifest.json"


def expr_int(value: int) -> dict[str, Any]:
    return {"kind": "int", "data": value}


def expr_bool(value: bool) -> dict[str, Any]:
    return {"kind": "bool", "data": value}


def expr_byte(value: int) -> dict[str, Any]:
    if not 0 <= value <= 255:
        raise ValueError(f"byte out of range: {value}")
    return {"kind": "byte", "data": value}


def expr_bytes(value: bytes) -> dict[str, Any]:
    return {"kind": "array", "data": [expr_byte(byte) for byte in value]}


def b(seed: int, length: int = 32) -> bytes:
    return bytes([seed] * length)


def sha256_bytes(data: bytes) -> str:
    return sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class Fixture:
    filename: str
    contract_name: str
    args: list[dict[str, Any]]
    abi: tuple[str, ...]


FIXTURES = (
    Fixture(
        filename="ValidatorStakingH001.sil",
        contract_name="ValidatorStakingH001",
        args=[expr_bytes(b(0))],
        abi=("verify",),
    ),
    Fixture(
        filename="ValidatorStakingState.sil",
        contract_name="ValidatorStakingState",
        args=[
            expr_bytes(b(1)),
            expr_int(10_000),
            expr_bool(True),
            expr_int(1),
            expr_int(1000),
            expr_int(0),
            expr_int(0),
            expr_bytes(b(0)),
            expr_int(0),
            expr_int(0),
            expr_int(0),
        ],
        abi=(
            "__covenant_entrypoint_auth_commitVote",
            "__covenant_entrypoint_auth_revealVote",
            "__covenant_entrypoint_auth_slashInvalidReveal",
            "__covenant_entrypoint_auth_requestWithdraw",
            "__covenant_entrypoint_auth_completeWithdraw",
        ),
    ),
    Fixture(
        filename="GuardianReputationState.sil",
        contract_name="GuardianReputationState",
        args=[
            expr_bytes(b(2)),
            expr_bytes(b(3)),
            expr_int(100),
            expr_int(1000),
            expr_int(0),
            expr_int(0),
            expr_int(1),
            expr_int(1),
        ],
        abi=(
            "__covenant_entrypoint_auth_register",
            "__covenant_entrypoint_auth_proposalAccepted",
            "__covenant_entrypoint_auth_proposalRejected",
        ),
    ),
    Fixture(
        filename="RuleStorageState.sil",
        contract_name="RuleStorageState",
        args=[
            expr_bytes(b(4)),
            expr_int(1),
            expr_int(0),
            expr_bytes(b(5)),
            expr_bytes(b(6)),
            expr_int(0),
            expr_bytes(b(7, 36)),
            expr_int(8500),
            expr_int(0),
            expr_int(0),
            expr_int(0),
            expr_int(0),
            expr_int(0),
            expr_int(0),
            expr_int(0),
            expr_int(0),
            expr_int(0),
            expr_int(0),
            expr_bool(False),
            expr_int(0),
        ],
        abi=(
            "__covenant_entrypoint_auth_submitProposal",
            "__covenant_entrypoint_auth_voteOnProposal",
            "__covenant_entrypoint_auth_finalizeProposal",
            "__covenant_entrypoint_auth_deactivateRule",
        ),
    ),
    Fixture(
        filename="CommunityDonationsState.sil",
        contract_name="CommunityDonationsState",
        args=[
            expr_bytes(b(8)),
            expr_int(0),
            expr_int(0),
            expr_int(0),
            expr_int(1),
            expr_int(0),
            expr_bytes(b(9)),
            expr_int(0),
            expr_bytes(b(13)),
            expr_int(0),
            expr_int(0),
            expr_int(0),
            expr_int(0),
            expr_bool(False),
            expr_bytes(b(14)),
            expr_bytes(b(0)),
            expr_int(0),
        ],
        abi=(
            "__covenant_entrypoint_auth_donateKas",
            "__covenant_entrypoint_auth_proposeDisbursement",
            "__covenant_entrypoint_auth_voteDisbursement",
            "__covenant_entrypoint_auth_executeDisbursement",
        ),
    ),
    Fixture(
        filename="DevIncentivePoolState.sil",
        contract_name="DevIncentivePoolState",
        args=[
            expr_int(1),
            expr_int(0),
            expr_int(0),
            expr_bytes(b(10)),
            expr_bytes(b(0)),
            expr_bytes(b(0)),
            expr_int(0),
            expr_int(1),
            expr_int(0),
            expr_int(0),
            expr_int(0),
            expr_int(0),
            expr_bool(False),
            expr_bool(False),
            expr_int(0),
            expr_bytes(b(12)),
        ],
        abi=(
            "__covenant_entrypoint_auth_proposeGrant",
            "__covenant_entrypoint_auth_voteGrant",
            "__covenant_entrypoint_auth_executeGrant",
        ),
    ),
    Fixture(
        filename="GovernanceAutoTuningState.sil",
        contract_name="GovernanceAutoTuningState",
        args=[
            expr_bytes(b(11)),
            expr_int(10_000),
            expr_int(1000),
            expr_int(8500),
            expr_int(6700),
            expr_int(100),
            expr_int(0),
            expr_int(100),
            expr_int(500),
            expr_int(10),
            expr_int(0),
            expr_int(0),
        ],
        abi=(
            "__covenant_entrypoint_auth_reportMetrics",
            "__covenant_entrypoint_auth_autoTune",
        ),
    ),
)


def run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    print(f"+ {' '.join(cmd)}", flush=True)
    proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    if proc.returncode != 0:
        if proc.stdout:
            print(proc.stdout, file=sys.stdout)
        if proc.stderr:
            print(proc.stderr, file=sys.stderr)
        proc.check_returncode()
    return proc


def build_silverc(silver_repo: Path) -> Path:
    run(["cargo", "build", "-p", "silverscript-lang", "--bin", "silverc"], silver_repo)
    silverc = silver_repo / "target" / "debug" / "silverc"
    if not silverc.exists():
        raise FileNotFoundError(f"silverc binary was not built: {silverc}")
    return silverc


def git_rev_parse(repo: Path, ref: str) -> str:
    return run(["git", "rev-parse", ref], repo).stdout.strip()


def write_constructor_args(fixture: Fixture, directory: Path) -> Path:
    args_path = directory / f"{fixture.contract_name}.ctor.json"
    args_path.write_text(json.dumps(fixture.args, indent=2) + "\n", encoding="utf-8")
    return args_path


def compile_fixture(silverc: Path, fixture: Fixture, output_dir: Path) -> dict[str, Any]:
    source = CONTRACT_DIR / fixture.filename
    if not source.exists():
        raise FileNotFoundError(f"missing fixture: {source}")

    with tempfile.TemporaryDirectory(prefix="prometheus-silverc-ctor.") as tmp:
        args_path = write_constructor_args(fixture, Path(tmp))
        artifact = output_dir / f"{fixture.contract_name}.json"
        run(
            [
                str(silverc),
                str(source),
                "--constructor-args",
                str(args_path),
                "-o",
                str(artifact),
            ],
            ROOT,
        )
        artifact_data = validate_artifact(artifact, fixture)
        return manifest_entry(source, artifact, artifact_data, fixture)


def validate_artifact(artifact: Path, fixture: Fixture) -> dict[str, Any]:
    data = json.loads(artifact.read_text(encoding="utf-8"))
    if data.get("contract_name") != fixture.contract_name:
        raise ValueError(f"{artifact}: contract_name mismatch")
    if not data.get("compiler_version"):
        raise ValueError(f"{artifact}: missing compiler_version")
    if not isinstance(data.get("script"), list) or not data["script"]:
        raise ValueError(f"{artifact}: script is empty or not a byte array")
    if not isinstance(data.get("state_layout"), dict):
        raise ValueError(f"{artifact}: missing state_layout")

    abi_names = {entry.get("name") for entry in data.get("abi", [])}
    missing = sorted(set(fixture.abi) - abi_names)
    if missing:
        raise ValueError(f"{artifact}: missing ABI entries: {', '.join(missing)}")
    return data


def manifest_entry(
    source: Path,
    artifact: Path,
    artifact_data: dict[str, Any],
    fixture: Fixture,
) -> dict[str, Any]:
    script = artifact_data["script"]
    if not all(isinstance(byte, int) and 0 <= byte <= 255 for byte in script):
        raise ValueError(f"{artifact}: script contains non-byte values")

    abi_names = [entry["name"] for entry in artifact_data["abi"]]
    return {
        "contract_name": fixture.contract_name,
        "source_file": str(source.relative_to(ROOT)),
        "artifact_file": artifact.name,
        "compiler_version": artifact_data["compiler_version"],
        "source_sha256": sha256_file(source),
        "constructor_args_sha256": sha256_bytes(canonical_json_bytes(fixture.args)),
        "artifact_sha256": sha256_file(artifact),
        "script_sha256": sha256_bytes(bytes(script)),
        "script_len": len(script),
        "state_layout": artifact_data["state_layout"],
        "abi": abi_names,
    }


def write_manifest(
    output_dir: Path,
    silver_ref: str,
    silver_commit: str,
    entries: list[dict[str, Any]],
) -> Path:
    manifest = {
        "schema_version": 1,
        "silverscript_ref": silver_ref,
        "silverscript_commit": silver_commit,
        "fixture_count": len(entries),
        "fixtures": entries,
    }
    manifest_path = output_dir / MANIFEST_NAME
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    validate_manifest(manifest_path, output_dir)
    return manifest_path


def validate_manifest(manifest_path: Path, output_dir: Path) -> None:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = manifest.get("fixtures")
    if manifest.get("schema_version") != 1:
        raise ValueError(f"{manifest_path}: unsupported schema_version")
    if manifest.get("fixture_count") != len(FIXTURES):
        raise ValueError(f"{manifest_path}: fixture_count mismatch")
    if not isinstance(entries, list) or len(entries) != len(FIXTURES):
        raise ValueError(f"{manifest_path}: fixtures list mismatch")

    expected_names = [fixture.contract_name for fixture in FIXTURES]
    actual_names = [entry.get("contract_name") for entry in entries]
    if actual_names != expected_names:
        raise ValueError(f"{manifest_path}: fixture order/name mismatch")

    for entry in entries:
        artifact = output_dir / entry["artifact_file"]
        if entry.get("artifact_sha256") != sha256_file(artifact):
            raise ValueError(f"{manifest_path}: artifact hash mismatch for {artifact.name}")
        source = ROOT / entry["source_file"]
        if entry.get("source_sha256") != sha256_file(source):
            raise ValueError(f"{manifest_path}: source hash mismatch for {source}")
        artifact_data = json.loads(artifact.read_text(encoding="utf-8"))
        script = artifact_data["script"]
        if entry.get("script_sha256") != sha256_bytes(bytes(script)):
            raise ValueError(f"{manifest_path}: script hash mismatch for {artifact.name}")
        if entry.get("script_len") != len(script):
            raise ValueError(f"{manifest_path}: script length mismatch for {artifact.name}")


def main() -> int:
    silver_repo = (
        Path(os.environ.get("SILVERSCRIPT_REPO", str(DEFAULT_SILVERSCRIPT_REPO)))
        .expanduser()
        .resolve()
    )
    silver_ref = os.environ.get("SILVERSCRIPT_REF", DEFAULT_SILVERSCRIPT_REF)
    output_dir = (
        Path(os.environ.get("PROMETHEUS_SILVERC_ARTIFACT_DIR", str(DEFAULT_OUTPUT_DIR)))
        .expanduser()
        .resolve()
    )

    ensure_silverscript_repo(silver_repo, silver_ref)
    silver_commit = git_rev_parse(silver_repo, "HEAD")
    silverc = build_silverc(silver_repo)

    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)

    entries = []
    for fixture in FIXTURES:
        entries.append(compile_fixture(silverc, fixture, output_dir))
        print(f"OK: {fixture.contract_name}", flush=True)

    manifest_path = write_manifest(output_dir, silver_ref, silver_commit, entries)
    print(f"Compiled {len(FIXTURES)} silverc artifacts into {output_dir}")
    print(f"Wrote release manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
