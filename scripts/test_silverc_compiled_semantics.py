#!/usr/bin/env python3
"""Unit tests for the compiled-artifact semantic gate (no compiler needed)."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import verify_silverc_compiled_semantics as gate  # noqa: E402

REPO = gate.REPO_ROOT
PIN = json.loads((REPO / gate.TOOLCHAIN_POLICY).read_text(encoding="utf-8"))[
    "silverscript"
]["commit"]
LAYOUT = {"fields": [{"name": "stake_kas", "type": "int"}]}


def built_entry(name: str, script: str = "1" * 64) -> dict[str, Any]:
    return {
        "contract_name": name,
        "source_file": f"modules/contracts/silverc/{name}.sil",
        "artifact_file": f"{name}.json",
        "compiler_version": "0.1.0",
        "source_sha256": "9" * 64,
        "constructor_args_sha256": "2" * 64,
        "artifact_sha256": "8" * 64,
        "script_sha256": script,
        "script_len": 100,
        "state_layout": LAYOUT,
        "abi": ["commit", "reveal"],
    }


def built_manifest(*entries: dict[str, Any]) -> dict[str, Any]:
    items = list(entries) or [built_entry("A"), built_entry("B")]
    return {
        "schema_version": 1,
        "silverscript_ref": PIN,
        "silverscript_commit": PIN,
        "fixture_count": len(items),
        "fixtures": items,
    }


class CompiledSemanticsGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        policy_dir = self.tmp / gate.TOOLCHAIN_POLICY.parent
        policy_dir.mkdir(parents=True)
        shutil.copy(REPO / gate.TOOLCHAIN_POLICY, self.tmp / gate.TOOLCHAIN_POLICY)
        self.built = built_manifest()
        self.expected = gate.project_built(self.built)
        self.built_path = self.tmp / "built.json"
        self.expected_path = self.tmp / "expected.json"
        self.save()

    def save(self) -> None:
        self.built_path.write_text(json.dumps(self.built), encoding="utf-8")
        self.expected_path.write_text(json.dumps(self.expected), encoding="utf-8")

    def errors(self) -> list[str]:
        return gate.verify(self.tmp, self.built_path, self.expected_path)

    def test_matching_manifest_passes(self) -> None:
        self.assertEqual(self.errors(), [])

    def test_source_only_change_passes(self) -> None:
        self.built["fixtures"][0]["source_sha256"] = "7" * 64
        self.built["fixtures"][0]["artifact_sha256"] = "6" * 64
        self.save()
        self.assertEqual(self.errors(), [])

    def test_script_change_rejected(self) -> None:
        self.built["fixtures"][0]["script_sha256"] = "3" * 64
        self.save()
        self.assertEqual(self.errors(), ["A: script_sha256 differs"])

    def test_each_gated_field_rejected(self) -> None:
        mutations = {
            "compiler_version": "0.2.0",
            "constructor_args_sha256": "4" * 64,
            "script_len": 101,
            "abi": ["commit"],
        }
        for key, value in mutations.items():
            with self.subTest(key=key):
                built = copy.deepcopy(self.built)
                built["fixtures"][1][key] = value
                self.built_path.write_text(json.dumps(built), encoding="utf-8")
                self.assertEqual(self.errors(), [f"B: {key} differs"])

    def test_state_layout_change_rejected(self) -> None:
        self.built["fixtures"][0]["state_layout"] = {"fields": []}
        self.save()
        self.assertEqual(self.errors(), ["A: state_layout_sha256 differs"])

    def test_fixture_set_and_order_rejected(self) -> None:
        self.built = built_manifest(built_entry("B"), built_entry("A"))
        self.save()
        self.expected = gate.project_built(built_manifest())
        self.save()
        self.assertIn("fixture set or order differs", self.errors())
        self.built = built_manifest(built_entry("A"))
        self.save()
        self.assertIn("fixture set or order differs", self.errors())

    def test_compiler_pin_drift_rejected(self) -> None:
        other = "0" * 40
        self.built["silverscript_commit"] = other
        self.save()
        self.assertIn(
            "built: silverscript_commit differs from toolchain pin", self.errors()
        )
        self.built["silverscript_commit"] = PIN
        self.expected["silverscript_commit"] = other
        self.save()
        self.assertIn(
            "expected: silverscript_commit differs from toolchain pin", self.errors()
        )

    def test_malformed_expected_rejected(self) -> None:
        cases: list[tuple[str, Any]] = [
            ("extra key", {**self.expected, "note": "x"}),
            ("bad hash", self._with_fixture(script_sha256="XYZ")),
            ("bool len", self._with_fixture(script_len=True)),
            ("zero len", self._with_fixture(script_len=0)),
            ("abi type", self._with_fixture(abi=[1])),
            ("empty", {**self.expected, "fixtures": []}),
        ]
        for label, value in cases:
            with self.subTest(label=label):
                self.expected_path.write_text(json.dumps(value), encoding="utf-8")
                errors = self.errors()
                self.assertEqual(len(errors), 1)
                self.assertTrue(errors[0].startswith("expected:"), errors)

    def test_duplicate_json_key_and_names_rejected(self) -> None:
        self.expected_path.write_text(
            '{"schema_version": 1, "schema_version": 1}', encoding="utf-8"
        )
        self.assertEqual(self.errors(), ["expected: duplicate JSON key"])
        dup = copy.deepcopy(self.expected)
        dup["fixtures"][1]["contract_name"] = "A"
        self.expected_path.write_text(json.dumps(dup), encoding="utf-8")
        self.assertEqual(
            self.errors(), ["expected: contract_name missing or duplicate"]
        )

    def test_malformed_built_rejected(self) -> None:
        for label, value in (
            ("schema", {**self.built, "schema_version": 2}),
            ("count", {**self.built, "fixture_count": 5}),
            ("field", {**self.built, "fixtures": [{"contract_name": "A"}]}),
        ):
            with self.subTest(label=label):
                self.built_path.write_text(json.dumps(value), encoding="utf-8")
                errors = self.errors()
                self.assertEqual(len(errors), 1)
                self.assertTrue(errors[0].startswith("built manifest:"), errors)

    def test_missing_and_symlinked_inputs_rejected(self) -> None:
        self.built_path.unlink()
        self.assertEqual(self.errors(), ["built manifest: file missing"])
        target = self.tmp / "real.json"
        target.write_text(json.dumps(self.built), encoding="utf-8")
        self.built_path.symlink_to(target)
        self.assertEqual(self.errors(), ["built manifest: symlink rejected"])

    def test_write_expected_round_trip(self) -> None:
        out = io.StringIO()
        path = self.tmp / "regenerated.json"
        with contextlib.redirect_stdout(out):
            code = gate.main(
                [
                    "--repo-root",
                    str(self.tmp),
                    "--built-manifest",
                    str(self.built_path),
                    "--expected",
                    str(path),
                    "--write-expected",
                ]
            )
        self.assertEqual(code, 0)
        self.assertEqual(gate.verify(self.tmp, self.built_path, path), [])

    def test_committed_expectation_is_well_formed_and_pinned(self) -> None:
        expected = gate.validate_expected(
            gate.load_json(REPO / gate.DEFAULT_EXPECTED, "expected")
        )
        self.assertEqual(expected["silverscript_commit"], PIN)
        self.assertEqual(len(expected["fixtures"]), 7)

    def _with_fixture(self, **changes: Any) -> dict[str, Any]:
        value = copy.deepcopy(self.expected)
        value["fixtures"][0].update(changes)
        return value


if __name__ == "__main__":
    unittest.main()
