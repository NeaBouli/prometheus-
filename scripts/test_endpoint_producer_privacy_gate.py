#!/usr/bin/env python3
"""Adversarial mutation tests for the GH-267 privacy gate verifier."""

from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable

SCRIPT = Path(__file__).with_name("verify_endpoint_producer_privacy_gate.py")
SPEC = importlib.util.spec_from_file_location("privacy_gate", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

REPO_ROOT = SCRIPT.parents[1]
SENTINEL = "zz_mutated_sentinel_zz"


def load_json(path: Path) -> Any:
    """Load one JSON document from disk."""
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    """Write one JSON document to disk."""
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def edit_wire(case: dict[str, Any], mutate: Callable[[dict[str, Any]], None]) -> None:
    """Rewrite one corpus wire in canonical compact form after mutation."""
    obj = json.loads(bytes.fromhex(case["wire_hex"]).decode("utf-8"))
    mutate(obj)
    case["wire_hex"] = json.dumps(obj, separators=(",", ":")).encode("utf-8").hex()


class EndpointProducerPrivacyGateTests(unittest.TestCase):
    root: Path

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        for rel in (MODULE.ARTIFACT_PATH, MODULE.STATUS_PATH, MODULE.VECTORS_PATH):
            dest = self.root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO_ROOT / rel, dest)

    def artifact_path(self) -> Path:
        """Return the temp copy of the threat-model artifact."""
        return self.root / MODULE.ARTIFACT_PATH

    def status_path(self) -> Path:
        """Return the temp copy of the public claim status."""
        return self.root / MODULE.STATUS_PATH

    def vectors_path(self) -> Path:
        """Return the temp copy of the shared corpus."""
        return self.root / MODULE.VECTORS_PATH

    def restore_fixture(self) -> None:
        """Restore all temp inputs so every table-driven mutation is isolated."""
        for rel in (MODULE.ARTIFACT_PATH, MODULE.STATUS_PATH, MODULE.VECTORS_PATH):
            shutil.copy2(REPO_ROOT / rel, self.root / rel)

    def mutate_artifact(self, mutate: Callable[[dict[str, Any]], None]) -> None:
        """Apply one mutation to the temp artifact copy."""
        data = load_json(self.artifact_path())
        mutate(data)
        write_json(self.artifact_path(), data)

    def mutate_status(self, mutate: Callable[[dict[str, Any]], None]) -> None:
        """Apply one mutation to the temp status copy."""
        data = load_json(self.status_path())
        mutate(data)
        write_json(self.status_path(), data)

    def mutate_vectors(self, mutate: Callable[[dict[str, Any]], None]) -> None:
        """Apply one mutation to the temp corpus copy."""
        data = load_json(self.vectors_path())
        mutate(data)
        write_json(self.vectors_path(), data)

    def assert_rejected(self, label: str) -> list[str]:
        """Require rejection with stable categories and no sentinel echo."""
        errors = MODULE.verify(self.root)
        self.assertNotEqual(errors, [], label)
        for error in errors:
            self.assertNotIn(SENTINEL, error, label)
        return errors

    def test_repository_root_passes(self) -> None:
        self.assertEqual(MODULE.verify(REPO_ROOT), [])

    def test_clean_temp_fixture_passes(self) -> None:
        self.assertEqual(MODULE.verify(self.root), [])

    def test_missing_files_are_rejected(self) -> None:
        for rel in (MODULE.ARTIFACT_PATH, MODULE.STATUS_PATH, MODULE.VECTORS_PATH):
            with self.subTest(file=str(rel)):
                (self.root / rel).unlink()
                errors = self.assert_rejected("missing file")
                self.assertTrue(any("missing or unreadable" in e for e in errors))
                shutil.copy2(REPO_ROOT / rel, self.root / rel)

    def test_malformed_json_is_rejected(self) -> None:
        for rel in (MODULE.ARTIFACT_PATH, MODULE.STATUS_PATH, MODULE.VECTORS_PATH):
            with self.subTest(file=str(rel)):
                (self.root / rel).write_text("{ not json", encoding="utf-8")
                errors = self.assert_rejected("malformed JSON")
                self.assertTrue(any("malformed JSON" in e for e in errors))
                shutil.copy2(REPO_ROOT / rel, self.root / rel)

    def test_non_utf8_json_is_categorized(self) -> None:
        self.artifact_path().write_bytes(b"\xff")
        errors = self.assert_rejected("non-UTF-8 artifact")
        self.assertTrue(any("missing or unreadable" in error for error in errors))

    def test_artifact_top_level_unknown_key_is_rejected(self) -> None:
        self.mutate_artifact(lambda d: d.update({SENTINEL: True}))
        errors = self.assert_rejected("unknown key")
        self.assertTrue(any("top-level keys drifted" in e for e in errors))

    def test_artifact_top_level_missing_key_is_rejected(self) -> None:
        for key in ("issue", "capabilities", "limitations"):
            with self.subTest(key=key):
                self.restore_fixture()
                self.mutate_artifact(lambda d: d.pop(key))
                self.assert_rejected("missing key")

    def test_artifact_top_level_type_drift_is_rejected(self) -> None:
        mutations = (
            ("schema_version", SENTINEL),
            ("issue", SENTINEL),
            ("as_of", 20260913),
            ("capabilities", [SENTINEL]),
            ("threat_actors", SENTINEL),
        )
        for key, value in mutations:
            with self.subTest(key=key):
                self.restore_fixture()
                self.mutate_artifact(lambda d: d.update({key: value}))
                self.assert_rejected("type drift")

    def test_every_false_capability_elevation_is_rejected(self) -> None:
        for name in MODULE.EXPECTED_CAPABILITIES:
            with self.subTest(capability=name):
                self.restore_fixture()
                self.mutate_artifact(lambda d: d["capabilities"].update({name: True}))
                errors = self.assert_rejected("capability elevated")
                self.assertTrue(any("capabilities" in e for e in errors))

    def test_capability_key_drift_is_rejected(self) -> None:
        self.mutate_artifact(lambda d: d["capabilities"].update({SENTINEL: False}))
        self.assert_rejected("capability key added")
        self.mutate_artifact(lambda d: d["capabilities"].pop(SENTINEL))
        self.mutate_artifact(lambda d: d["capabilities"].pop("transport"))
        self.assert_rejected("capability key removed")

    def test_allowed_field_reorder_is_rejected(self) -> None:
        def reorder(data: dict[str, Any]) -> None:
            fields = data["allowed_statement_fields"]
            fields[0], fields[1] = fields[1], fields[0]

        self.mutate_artifact(reorder)
        errors = self.assert_rejected("field reorder")
        self.assertTrue(any("allowed statement fields" in e for e in errors))

    def test_allowed_field_add_is_rejected(self) -> None:
        self.mutate_artifact(lambda d: d["allowed_statement_fields"].append(SENTINEL))
        self.assert_rejected("field add")

    def test_allowed_field_remove_is_rejected(self) -> None:
        self.mutate_artifact(lambda d: d["allowed_statement_fields"].pop())
        self.assert_rejected("field remove")

    def test_list_weakening_is_rejected(self) -> None:
        for key in (
            "threat_actors",
            "abuse_cases",
            "protected_data_classes",
            "prohibited_raw_data_classes",
            "future_requirements",
            "trust_boundaries",
            "promotion_gates",
            "limitations",
        ):
            with self.subTest(key=key):
                self.restore_fixture()
                self.mutate_artifact(lambda d: d[key].pop())
                self.assert_rejected("list weakened")

    def test_list_value_drift_is_rejected(self) -> None:
        for key in (
            "threat_actors",
            "abuse_cases",
            "protected_data_classes",
            "prohibited_raw_data_classes",
            "future_requirements",
            "trust_boundaries",
            "promotion_gates",
            "limitations",
        ):
            with self.subTest(key=key):
                self.restore_fixture()
                self.mutate_artifact(lambda d: d[key].__setitem__(0, SENTINEL))
                self.assert_rejected("list value drift")

    def test_privacy_rejection_case_drift_is_rejected(self) -> None:
        self.mutate_artifact(
            lambda d: d["required_privacy_rejection_cases"][0].update(
                {"forbidden_wire_key": SENTINEL}
            )
        )
        self.assert_rejected("privacy case key drift")
        self.restore_fixture()
        self.mutate_artifact(lambda d: d["required_privacy_rejection_cases"].pop())
        self.assert_rejected("privacy case removed")

    def test_current_state_drift_is_rejected(self) -> None:
        self.mutate_artifact(
            lambda d: d["current_state"].update({"data_retention": SENTINEL})
        )
        self.assert_rejected("retention drift")
        self.mutate_artifact(
            lambda d: d["current_state"].update(
                {"data_retention": "none", "runtime_collection_authorized": True}
            )
        )
        self.assert_rejected("runtime authorization drift")

    def test_scope_and_identity_drift_are_rejected(self) -> None:
        for key in ("classification", "scope"):
            with self.subTest(key=key):
                self.restore_fixture()
                self.mutate_artifact(lambda d: d.update({key: SENTINEL}))
                self.assert_rejected("identity drift")

    def test_status_capability_drift_is_rejected(self) -> None:
        mutations = (
            ("gh_258", "real_time_endpoint_sensor"),
            ("gh_258", "automatic_quarantine_authorized"),
            ("gh_264", "endpoint_collection"),
            ("gh_264", "transport"),
            ("gh_264", "production_authority"),
            ("gh_267", "endpoint_collection"),
            ("gh_267", "runtime_collection_authorized"),
            ("gh_267", "privacy_safety_proven"),
            ("gh_267", "hidden_sensor_absence_proven"),
            ("gh_267", "production_authority"),
        )
        for section, field in mutations:
            with self.subTest(section=section, field=field):
                self.restore_fixture()
                self.mutate_status(
                    lambda d: d["post_audit_updates"][section].update({field: True})
                )
                self.assert_rejected("status capability drift")

    def test_status_endpoint_classification_drift_is_rejected(self) -> None:
        self.mutate_status(
            lambda d: d["classifications"]["endpoint_detection_and_response"].update(
                {"real_time_sensor_implemented": True}
            )
        )
        self.assert_rejected("endpoint sensor drift")
        self.mutate_status(
            lambda d: d["classifications"]["endpoint_detection_and_response"].update(
                {"real_time_sensor_implemented": False, "status": SENTINEL}
            )
        )
        self.assert_rejected("endpoint status drift")

    def test_status_gh267_identity_drift_is_rejected(self) -> None:
        mutations = (
            ("issue", 999),
            ("as_of", "2026-09-12"),
            ("status", "production"),
            ("classification", "endpoint_producer"),
            ("artifact", "docs/evidence/other.json"),
            ("security_ci_enforced", False),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                self.restore_fixture()
                self.mutate_status(
                    lambda d: d["post_audit_updates"]["gh_267"].update({field: value})
                )
                self.assert_rejected("GH-267 identity drift")

    def test_missing_or_malformed_gh267_status_is_rejected(self) -> None:
        for value in (None, [], "invalid", 267):
            with self.subTest(value=value):
                self.restore_fixture()
                self.mutate_status(
                    lambda d: d["post_audit_updates"].update({"gh_267": value})
                )
                self.assert_rejected("GH-267 malformed status")

    def test_endpoint_privacy_boundary_elevation_is_rejected(self) -> None:
        for field in (
            "runtime_collection_authorized",
            "hidden_sensor_absence_proven",
        ):
            with self.subTest(field=field):
                self.restore_fixture()
                self.mutate_status(
                    lambda d: d["classifications"][
                        "endpoint_detection_and_response"
                    ].update({field: True})
                )
                self.assert_rejected("endpoint privacy boundary drift")

    def test_status_gh264_scalar_drift_is_rejected(self) -> None:
        for field in ("closed_domains", "closed_signals"):
            with self.subTest(field=field):
                self.restore_fixture()
                self.mutate_status(
                    lambda d: d["post_audit_updates"]["gh_264"].update({field: 1})
                )
                self.assert_rejected("GH-264 scalar drift")
        self.restore_fixture()
        self.mutate_status(
            lambda d: d["post_audit_updates"]["gh_264"].update(
                {"max_canonical_bytes": 1}
            )
        )
        errors = self.assert_rejected("GH-264 max size drift")
        self.assertTrue(any("wire size exceeds" in e for e in errors))

        self.restore_fixture()
        self.mutate_status(
            lambda d: d["post_audit_updates"]["gh_264"].update(
                {"max_canonical_bytes": 513}
            )
        )
        errors = self.assert_rejected("GH-264 max size weakening")
        self.assertTrue(any("maximum wire size drifted" in e for e in errors))

    def test_boolean_schema_versions_are_rejected(self) -> None:
        self.mutate_status(
            lambda d: d["post_audit_updates"]["gh_264"].update({"schema_version": True})
        )
        self.assert_rejected("boolean GH-264 schema version")

        self.restore_fixture()
        self.mutate_vectors(lambda d: d.update({"vector_schema_version": True}))
        self.assert_rejected("boolean corpus schema version")

    def test_valid_corpus_count_drift_is_rejected(self) -> None:
        self.mutate_vectors(lambda d: d["valid_cases"].pop())
        errors = self.assert_rejected("valid count drift")
        self.assertTrue(any("valid corpus count drifted" in e for e in errors))

    def test_invalid_corpus_count_drift_is_rejected(self) -> None:
        self.mutate_vectors(lambda d: d["invalid_cases"].pop(0))
        errors = self.assert_rejected("invalid count drift")
        self.assertTrue(any("invalid corpus count drifted" in e for e in errors))

    def test_valid_wire_extra_field_is_rejected(self) -> None:
        def add_field(data: dict[str, Any]) -> None:
            edit_wire(data["valid_cases"][0], lambda obj: obj.update({SENTINEL: "x"}))

        self.mutate_vectors(add_field)
        errors = self.assert_rejected("wire extra field")
        self.assertTrue(any("valid wire fields drifted" in e for e in errors))

    def test_valid_wire_missing_field_is_rejected(self) -> None:
        def drop_field(data: dict[str, Any]) -> None:
            edit_wire(data["valid_cases"][0], lambda obj: obj.pop("network_id"))

        self.mutate_vectors(drop_field)
        self.assert_rejected("wire missing field")

    def test_single_scalar_array_wire_is_categorized(self) -> None:
        def replace_wire(data: dict[str, Any]) -> None:
            data["valid_cases"][0]["wire_hex"] = b"[5]".hex()

        self.mutate_vectors(replace_wire)
        errors = self.assert_rejected("non-object wire")
        self.assertTrue(any("valid wire malformed" in error for error in errors))

    def test_valid_wire_reordered_fields_are_rejected(self) -> None:
        def reorder(data: dict[str, Any]) -> None:
            def swap(obj: dict[str, Any]) -> None:
                items = list(obj.items())
                items[0], items[1] = items[1], items[0]
                obj.clear()
                obj.update(items)

            edit_wire(data["valid_cases"][0], swap)

        self.mutate_vectors(reorder)
        self.assert_rejected("wire reorder")

    def test_derived_signal_drift_is_rejected(self) -> None:
        def drift(data: dict[str, Any]) -> None:
            edit_wire(
                data["valid_cases"][0], lambda obj: obj.update({"signal": SENTINEL})
            )

        self.mutate_vectors(drift)
        errors = self.assert_rejected("signal drift")
        self.assertTrue(any("derived signals diverge" in e for e in errors))

    def test_derived_domain_drift_is_rejected(self) -> None:
        def drift(data: dict[str, Any]) -> None:
            edit_wire(
                data["valid_cases"][1], lambda obj: obj.update({"domain": SENTINEL})
            )

        self.mutate_vectors(drift)
        errors = self.assert_rejected("domain drift")
        self.assertTrue(any("derived domains diverge" in e for e in errors))

    def test_privacy_vector_missing_is_rejected(self) -> None:
        def remove(data: dict[str, Any]) -> None:
            data["invalid_cases"] = [
                case
                for case in data["invalid_cases"]
                if case["name"] != "privacy_process_name_field"
            ]
            data["valid_cases"].append(copy.deepcopy(data["valid_cases"][0]))

        self.mutate_vectors(remove)
        errors = self.assert_rejected("privacy vector missing")
        self.assertTrue(any("privacy rejection case missing" in e for e in errors))

    def test_privacy_vector_extra_key_drift_is_rejected(self) -> None:
        def drift(data: dict[str, Any]) -> None:
            for case in data["invalid_cases"]:
                if case["name"] == "privacy_path_field":
                    edit_wire(
                        case,
                        lambda obj: (
                            obj.pop("path"),
                            obj.update({SENTINEL: "x"}),
                        ),
                    )

        self.mutate_vectors(drift)
        errors = self.assert_rejected("privacy vector key drift")
        self.assertTrue(
            any("privacy rejection case fields drifted" in e for e in errors)
        )

    def test_privacy_vector_dropped_allowed_field_is_rejected(self) -> None:
        def drift(data: dict[str, Any]) -> None:
            for case in data["invalid_cases"]:
                if case["name"] == "privacy_host_identifier_field":
                    edit_wire(case, lambda obj: obj.pop("window_seconds"))

        self.mutate_vectors(drift)
        errors = self.assert_rejected("privacy vector field dropped")
        self.assertTrue(
            any("privacy rejection case fields drifted" in e for e in errors)
        )

    def test_errors_are_stable_categories(self) -> None:
        self.mutate_artifact(lambda d: d.update({"issue": 999}))
        first = MODULE.verify(self.root)
        second = MODULE.verify(self.root)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
