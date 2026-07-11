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


def write_constructor_args(fixture: Fixture, directory: Path) -> Path:
    args_path = directory / f"{fixture.contract_name}.ctor.json"
    args_path.write_text(json.dumps(fixture.args, indent=2) + "\n", encoding="utf-8")
    return args_path


def compile_fixture(silverc: Path, fixture: Fixture, output_dir: Path) -> None:
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
        validate_artifact(artifact, fixture)


def validate_artifact(artifact: Path, fixture: Fixture) -> None:
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
    silverc = build_silverc(silver_repo)

    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)

    for fixture in FIXTURES:
        compile_fixture(silverc, fixture, output_dir)
        print(f"OK: {fixture.contract_name}", flush=True)

    print(f"Compiled {len(FIXTURES)} silverc artifacts into {output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
