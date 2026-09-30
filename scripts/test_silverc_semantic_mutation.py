#!/usr/bin/env python3
"""Negative regression for GH-283: literal checks miss semantic mutations.

Compiles behavior-changing mutants of current-silverc fixtures with the pinned
silverc binary. Each mutant keeps every literal the contract lint step greps
for, and each must still be rejected by the compiled-artifact semantic gate.
The unmutated fixture must compile to exactly the expected script bytes.

Requires a silverc binary built by scripts/smoke_silverc_artifacts.py and that
run's manifest. Offline; no deployment or broadcast.
"""

from __future__ import annotations

import argparse
import copy
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import smoke_silverc_artifacts as smoke  # noqa: E402
import verify_silverc_compiled_semantics as gate  # noqa: E402


@dataclass(frozen=True)
class Mutation:
    mutation_id: str
    fixture: str
    old: str
    new: str
    # Literals the contract lint step (ci.yml contract-check) requires.
    lint_literals: tuple[str, ...]


VALIDATOR_LITERALS = (
    "MIN_STAKE_KAS = 10000",
    "BOND_PERCENT = 10",
    "COOLDOWN_BLOCKS = 100800",
    "commitmentHash(vote, salt, prev_state.committed_at_block)",
)
MUTATIONS = (
    Mutation(
        "bond-floor-inverted",
        "ValidatorStakingState",
        "require(new_bond_kas >= prev_state.stake_kas * BOND_PERCENT / 100);",
        "require(new_bond_kas <= prev_state.stake_kas * BOND_PERCENT / 100);",
        VALIDATOR_LITERALS,
    ),
    Mutation(
        "reveal-commitment-check-inverted",
        "ValidatorStakingState",
        "require(commitmentHash(vote, salt, prev_state.committed_at_block) "
        "== prev_state.commitment);",
        "require(commitmentHash(vote, salt, prev_state.committed_at_block) "
        "!= prev_state.commitment);",
        VALIDATOR_LITERALS,
    ),
)


def fixture_by_name(name: str) -> smoke.Fixture:
    for fixture in smoke.FIXTURES:
        if fixture.contract_name == name:
            return fixture
    raise SystemExit(f"unknown fixture {name}")


def compile_source(
    silverc: Path, fixture: smoke.Fixture, source: str
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="prometheus-silverc-mutant.") as tmp:
        work = Path(tmp)
        source_path = work / fixture.filename
        source_path.write_text(source, encoding="utf-8")
        args_path = smoke.write_constructor_args(fixture, work)
        artifact = work / f"{fixture.contract_name}.json"
        subprocess.run(
            [
                str(silverc),
                str(source_path),
                "--constructor-args",
                str(args_path),
                "-o",
                str(artifact),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        data = smoke.validate_artifact(artifact, fixture)
    script = bytes(data["script"])
    return {
        "contract_name": fixture.contract_name,
        "compiler_version": data["compiler_version"],
        "constructor_args_sha256": sha256(
            smoke.canonical_json_bytes(fixture.args)
        ).hexdigest(),
        "script_sha256": sha256(script).hexdigest(),
        "script_len": len(script),
        "abi": [entry["name"] for entry in data["abi"]],
        "state_layout": data["state_layout"],
    }


def replace_fixture(built: dict[str, Any], entry: dict[str, Any]) -> dict[str, Any]:
    mutated = copy.deepcopy(built)
    for index, existing in enumerate(mutated["fixtures"]):
        if existing["contract_name"] == entry["contract_name"]:
            merged = dict(existing)
            merged.update(entry)
            mutated["fixtures"][index] = merged
            return mutated
    raise SystemExit(f"fixture {entry['contract_name']} not in built manifest")


def gate_errors(root: Path, manifest: dict[str, Any]) -> list[str]:
    with tempfile.TemporaryDirectory(prefix="prometheus-silverc-gate.") as tmp:
        path = Path(tmp) / "manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return gate.verify(root, path, root / gate.DEFAULT_EXPECTED)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--silverc", type=Path, required=True)
    parser.add_argument("--built-manifest", type=Path, required=True)
    args = parser.parse_args(argv)
    root = gate.REPO_ROOT
    built = json.loads(args.built_manifest.read_text(encoding="utf-8"))
    failures: list[str] = []

    if gate_errors(root, built):
        failures.append("baseline: built manifest does not match the expectation")

    for mutation in MUTATIONS:
        fixture = fixture_by_name(mutation.fixture)
        original = (smoke.CONTRACT_DIR / fixture.filename).read_text(encoding="utf-8")
        if original.count(mutation.old) != 1:
            failures.append(f"{mutation.mutation_id}: anchor not found exactly once")
            continue
        baseline_entry = compile_source(args.silverc, fixture, original)
        if gate_errors(root, replace_fixture(built, baseline_entry)):
            failures.append(f"{mutation.mutation_id}: unmutated recompile differs")
        mutant = original.replace(mutation.old, mutation.new)
        missing = [lit for lit in mutation.lint_literals if lit not in mutant]
        if missing:
            failures.append(f"{mutation.mutation_id}: mutant lost lint literals")
            continue
        entry = compile_source(args.silverc, fixture, mutant)
        errors = gate_errors(root, replace_fixture(built, entry))
        if f"{fixture.contract_name}: script_sha256 differs" not in errors:
            failures.append(f"{mutation.mutation_id}: semantic mutant was not rejected")
        else:
            print(f"OK: {mutation.mutation_id} keeps lint literals and is rejected")

    if failures:
        print("silverc semantic mutation regression: FAIL", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(
        f"silverc semantic mutation regression: OK ({len(MUTATIONS)} mutants rejected)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
