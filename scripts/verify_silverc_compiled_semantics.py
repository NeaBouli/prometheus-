#!/usr/bin/env python3
"""Compiled-artifact semantic gate for the current-silverc contract fixtures.

Compares a manifest produced by scripts/smoke_silverc_artifacts.py (pinned
compiler, fixed constructor arguments) with the reviewed expectation in
modules/contracts/silverc/expected-compiled-artifacts.json. Any change to the
compiled script bytes, ABI, state layout, constructor arguments, or compiler
revision fails, even when the source keeps every literal the lint step greps
for. Source-only edits that compile to identical bytes are accepted.

Offline; reads only the two manifests. Does not compile, deploy, or broadcast.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_EXPECTED = Path("modules/contracts/silverc/expected-compiled-artifacts.json")
TOOLCHAIN_POLICY = Path("docs/architecture/toolchain-pins.json")
SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX40 = re.compile(r"[0-9a-f]{40}")
EXPECTED_KEYS = frozenset({"schema_version", "silverscript_commit", "fixtures"})
FIXTURE_KEYS = frozenset(
    {
        "contract_name",
        "compiler_version",
        "constructor_args_sha256",
        "script_sha256",
        "script_len",
        "abi",
        "state_layout_sha256",
    }
)


class GateError(ValueError):
    """Raised for malformed input files."""


def canonical_sha256(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path, label: str) -> Any:
    try:
        if path.is_symlink():
            raise GateError(f"{label}: symlink rejected")
        data = path.read_bytes()
    except FileNotFoundError:
        raise GateError(f"{label}: file missing") from None
    except OSError:
        raise GateError(f"{label}: unreadable") from None
    if len(data) > MAX_MANIFEST_BYTES:
        raise GateError(f"{label}: file too large")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        keys = [key for key, _ in pairs]
        if len(keys) != len(set(keys)):
            raise GateError(f"{label}: duplicate JSON key")
        return dict(pairs)

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise GateError(f"{label}: invalid JSON") from None


def pinned_silverscript_commit(root: Path) -> str:
    policy = load_json(root / TOOLCHAIN_POLICY, "toolchain policy")
    try:
        commit = policy["silverscript"]["commit"]
    except (KeyError, TypeError):
        raise GateError("toolchain policy: silverscript commit missing") from None
    if not isinstance(commit, str) or not HEX40.fullmatch(commit):
        raise GateError("toolchain policy: silverscript commit malformed")
    return commit


def project_built(built: Any) -> dict[str, Any]:
    """Reduce a smoke-build manifest to the gated, source-independent fields."""
    if not isinstance(built, dict) or built.get("schema_version") != 1:
        raise GateError("built manifest: unsupported schema")
    fixtures = built.get("fixtures")
    commit = built.get("silverscript_commit")
    if not isinstance(fixtures, list) or not isinstance(commit, str):
        raise GateError("built manifest: fixtures or commit missing")
    if built.get("fixture_count") != len(fixtures):
        raise GateError("built manifest: fixture_count mismatch")
    projected = []
    for entry in fixtures:
        if not isinstance(entry, dict):
            raise GateError("built manifest: fixture entry malformed")
        try:
            projected.append(
                {
                    "contract_name": entry["contract_name"],
                    "compiler_version": entry["compiler_version"],
                    "constructor_args_sha256": entry["constructor_args_sha256"],
                    "script_sha256": entry["script_sha256"],
                    "script_len": entry["script_len"],
                    "abi": entry["abi"],
                    "state_layout_sha256": canonical_sha256(entry["state_layout"]),
                }
            )
        except KeyError:
            raise GateError("built manifest: fixture field missing") from None
    return {
        "schema_version": SCHEMA_VERSION,
        "silverscript_commit": commit,
        "fixtures": projected,
    }


def validate_expected(expected: Any) -> dict[str, Any]:
    if not isinstance(expected, dict) or set(expected) != EXPECTED_KEYS:
        raise GateError("expected: top-level keys mismatch")
    if expected["schema_version"] != SCHEMA_VERSION:
        raise GateError("expected: unsupported schema_version")
    commit = expected["silverscript_commit"]
    if not isinstance(commit, str) or not HEX40.fullmatch(commit):
        raise GateError("expected: silverscript_commit malformed")
    fixtures = expected["fixtures"]
    if not isinstance(fixtures, list) or not fixtures:
        raise GateError("expected: fixtures missing")
    names: set[str] = set()
    for entry in fixtures:
        if not isinstance(entry, dict) or set(entry) != FIXTURE_KEYS:
            raise GateError("expected: fixture keys mismatch")
        name = entry["contract_name"]
        if not isinstance(name, str) or not name or name in names:
            raise GateError("expected: contract_name missing or duplicate")
        names.add(name)
        for key in ("constructor_args_sha256", "script_sha256", "state_layout_sha256"):
            if not isinstance(entry[key], str) or not HEX64.fullmatch(entry[key]):
                raise GateError(f"expected: {name} {key} malformed")
        script_len = entry["script_len"]
        if (
            isinstance(script_len, bool)
            or not isinstance(script_len, int)
            or script_len <= 0
        ):
            raise GateError(f"expected: {name} script_len malformed")
        abi = entry["abi"]
        if not isinstance(abi, list) or not all(isinstance(a, str) for a in abi):
            raise GateError(f"expected: {name} abi malformed")
        if (
            not isinstance(entry["compiler_version"], str)
            or not entry["compiler_version"]
        ):
            raise GateError(f"expected: {name} compiler_version malformed")
    return expected


def compare(expected: dict[str, Any], actual: dict[str, Any], pin: str) -> list[str]:
    errors: list[str] = []
    if expected["silverscript_commit"] != pin:
        errors.append("expected: silverscript_commit differs from toolchain pin")
    if actual["silverscript_commit"] != pin:
        errors.append("built: silverscript_commit differs from toolchain pin")
    exp_names = [entry["contract_name"] for entry in expected["fixtures"]]
    act_names = [entry["contract_name"] for entry in actual["fixtures"]]
    if exp_names != act_names:
        errors.append("fixture set or order differs")
    actual_by_name = {entry["contract_name"]: entry for entry in actual["fixtures"]}
    for exp in expected["fixtures"]:
        name = exp["contract_name"]
        act = actual_by_name.get(name)
        if act is None:
            continue
        for key in sorted(FIXTURE_KEYS - {"contract_name"}):
            if exp[key] != act.get(key):
                errors.append(f"{name}: {key} differs")
    return sorted(set(errors))


def verify(root: Path, built_path: Path, expected_path: Path) -> list[str]:
    try:
        pin = pinned_silverscript_commit(root)
        expected = validate_expected(load_json(expected_path, "expected"))
        actual = project_built(load_json(built_path, "built manifest"))
    except GateError as exc:
        return [str(exc)]
    return compare(expected, actual, pin)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare compiled silverc fixtures with the reviewed expectation."
    )
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--built-manifest", type=Path, required=True)
    parser.add_argument("--expected", type=Path, default=None)
    parser.add_argument(
        "--write-expected",
        action="store_true",
        help="Regenerate the expectation from the built manifest (reviewed change only).",
    )
    args = parser.parse_args(argv)
    root: Path = args.repo_root
    expected_path: Path = args.expected or root / DEFAULT_EXPECTED
    if args.write_expected:
        try:
            projected = project_built(load_json(args.built_manifest, "built manifest"))
            validate_expected(projected)
        except GateError as exc:
            print(f"silverc compiled semantics: FAIL\n- {exc}", file=sys.stderr)
            return 1
        expected_path.write_text(
            json.dumps(projected, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(
            f"silverc compiled semantics: wrote {len(projected['fixtures'])} fixtures"
        )
        return 0
    errors = verify(root, args.built_manifest, expected_path)
    if errors:
        print("silverc compiled semantics: FAIL", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("silverc compiled semantics: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
