#!/usr/bin/env python3
"""Unit tests for the public claim consistency gate."""

from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).with_name("verify_public_claim_consistency.py")
SPEC = importlib.util.spec_from_file_location("claim_consistency", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PublicClaimConsistencyTests(unittest.TestCase):
    status: dict[str, Any]

    @classmethod
    def setUpClass(cls) -> None:
        status_path = SCRIPT.parents[1] / MODULE.STATUS_PATH
        cls.status = json.loads(status_path.read_text(encoding="utf-8"))

    def test_canonical_status_passes(self) -> None:
        self.assertEqual(MODULE.validate_status(self.status), [])

    def test_prom_staking_is_rejected(self) -> None:
        changed = copy.deepcopy(self.status)
        changed["classifications"]["validators"]["prom_staking"] = True
        self.assertIn("validators must stake KAS", MODULE.validate_status(changed)[0])

    def test_incomplete_allocations_are_rejected(self) -> None:
        changed = copy.deepcopy(self.status)
        del changed["classifications"]["prom"]["year_one_allocation_percent"][
            "community"
        ]
        self.assertIn("allocation categories", MODULE.validate_status(changed)[0])

    def test_active_guardian_market_is_rejected(self) -> None:
        changed = copy.deepcopy(self.status)
        changed["classifications"]["guardian_economics"][
            "active_rewards_or_market_price"
        ] = True
        self.assertTrue(
            any("market price" in error for error in MODULE.validate_status(changed))
        )

    def test_phi3_stub_authority_is_rejected(self) -> None:
        changed = copy.deepcopy(self.status)
        changed["classifications"]["light_client"][
            "phi3_stub_authority"
        ] = "heuristic_quarantine"
        self.assertTrue(
            any("Phi-3 stub" in error for error in MODULE.validate_status(changed))
        )

    def test_operated_p2p_claim_is_rejected(self) -> None:
        changed = copy.deepcopy(self.status)
        changed["classifications"]["light_client"]["p2p_reporting"] = "operated"
        self.assertTrue(
            any("P2P reporting" in error for error in MODULE.validate_status(changed))
        )

    def test_v1_submission_scope_drift_is_rejected(self) -> None:
        changed = copy.deepcopy(self.status)
        changed["classifications"]["light_client"]["p2p_v1_submission"] = "public"
        self.assertTrue(
            any("v1 submission" in error for error in MODULE.validate_status(changed))
        )

    def test_gh_234_post_audit_scope_drift_is_rejected(self) -> None:
        changed = copy.deepcopy(self.status)
        changed["post_audit_updates"]["gh_234"]["public_or_multihost_v2"] = True
        self.assertTrue(
            any(
                "public or multi-host" in error
                for error in MODULE.validate_status(changed)
            )
        )

    def test_missing_gh_234_post_audit_record_is_rejected(self) -> None:
        changed = copy.deepcopy(self.status)
        del changed["post_audit_updates"]["gh_234"]
        errors = MODULE.validate_status(changed)
        self.assertTrue(any("GH-234 v2 submission" in error for error in errors))
        self.assertTrue(any("production authority" in error for error in errors))

    def test_incomplete_gh_234_exact_main_evidence_is_rejected(self) -> None:
        changed = copy.deepcopy(self.status)
        del changed["post_audit_updates"]["gh_234"]["exact_main_runs"]["pages"]
        self.assertTrue(
            any("run evidence" in error for error in MODULE.validate_status(changed))
        )

    def test_malformed_gh_234_merge_commit_is_rejected(self) -> None:
        changed = copy.deepcopy(self.status)
        changed["post_audit_updates"]["gh_234"]["merge_commit"] = "f146fb2"
        self.assertTrue(
            any("merge commit" in error for error in MODULE.validate_status(changed))
        )

    def test_gh_238_remote_or_authorizing_scope_drift_is_rejected(self) -> None:
        for field in (
            "remote_run",
            "evidence_record",
            "independent_host_proof",
            "network_or_infrastructure_action",
            "production_authority",
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.status)
                changed["post_audit_updates"]["gh_238"][field] = True
                self.assertTrue(
                    any(
                        f"GH-238 {field}" in error
                        for error in MODULE.validate_status(changed)
                    )
                )
        for field, value in (
            ("transport", "direct-quic-v2"),
            ("protocol", "/prometheus/threat-hint/3.0.0"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.status)
                changed["post_audit_updates"]["gh_238"][field] = value
                self.assertTrue(
                    any(
                        "GH-238 must remain repository-only" in error
                        for error in MODULE.validate_status(changed)
                    )
                )

    def test_gh_238_status_drift_is_rejected(self) -> None:
        changed = copy.deepcopy(self.status)
        changed["post_audit_updates"]["gh_238"][
            "status"
        ] = "repository_preparation_implemented_and_locally_tested"
        self.assertTrue(
            any(
                "exact-main verification" in error
                for error in MODULE.validate_status(changed)
            )
        )

    def test_gh_238_pull_request_identity_drift_is_rejected(self) -> None:
        changed = copy.deepcopy(self.status)
        changed["post_audit_updates"]["gh_238"]["pull_request"] = 238
        self.assertTrue(
            any(
                "machine status identity" in error
                for error in MODULE.validate_status(changed)
            )
        )

    def test_malformed_gh_238_merge_commit_is_rejected(self) -> None:
        changed = copy.deepcopy(self.status)
        changed["post_audit_updates"]["gh_238"]["merge_commit"] = "912d96d"
        self.assertTrue(
            any("merge commit" in error for error in MODULE.validate_status(changed))
        )

    def test_incomplete_gh_238_exact_main_evidence_is_rejected(self) -> None:
        changed = copy.deepcopy(self.status)
        del changed["post_audit_updates"]["gh_238"]["exact_main_runs"]["pages"]
        self.assertTrue(
            any("run evidence" in error for error in MODULE.validate_status(changed))
        )

    def test_non_positive_gh_238_run_ids_are_rejected(self) -> None:
        changed = copy.deepcopy(self.status)
        changed["post_audit_updates"]["gh_238"]["exact_main_runs"]["pages"] = 0
        self.assertTrue(
            any(
                "positive integers" in error
                for error in MODULE.validate_status(changed)
            )
        )

    def test_boolean_gh_238_run_ids_are_rejected(self) -> None:
        changed = copy.deepcopy(self.status)
        changed["post_audit_updates"]["gh_238"]["exact_main_runs"]["pages"] = True
        self.assertTrue(
            any(
                "positive integers" in error
                for error in MODULE.validate_status(changed)
            )
        )

    def test_gh_238_public_surface_drift_is_rejected(self) -> None:
        root = SCRIPT.parents[1]
        run_id = str(
            self.status["post_audit_updates"]["gh_238"]["exact_main_runs"]["pages"]
        )
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            status_target = tmp_root / MODULE.STATUS_PATH
            status_target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(root / MODULE.STATUS_PATH, status_target)
            for relative in MODULE.PUBLIC_FILES:
                target = tmp_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(root / relative, target)
            drifted = tmp_root / "docs/roadmap.md"
            drifted.write_text(
                drifted.read_text(encoding="utf-8").replace(run_id, "0"),
                encoding="utf-8",
            )
            errors = MODULE.verify(tmp_root)
            self.assertTrue(
                any(
                    "docs/roadmap.md" in error and "GH-238 exact-main" in error
                    for error in errors
                )
            )

    def test_missing_gh_238_status_is_rejected(self) -> None:
        changed = copy.deepcopy(self.status)
        del changed["post_audit_updates"]["gh_238"]
        errors = MODULE.validate_status(changed)
        self.assertTrue(any("GH-238 machine status" in error for error in errors))
        self.assertTrue(any("GH-238 remote_run" in error for error in errors))

    def test_gh_242_authority_or_behavior_drift_is_rejected(self) -> None:
        for field in (
            "caller_supplied_committee_or_signers",
            "ballot_wire_or_ensemble_formula_changed",
            "external_membership_authority",
            "key_ownership_or_rotation_proven",
            "sybil_resistance_proven",
            "on_chain_attestation",
            "production_authority",
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.status)
                changed["post_audit_updates"]["gh_242"][field] = True
                errors = MODULE.validate_status(changed)
                self.assertTrue(any("GH-242" in error for error in errors))

    def test_missing_gh_242_status_is_rejected(self) -> None:
        changed = copy.deepcopy(self.status)
        del changed["post_audit_updates"]["gh_242"]
        errors = MODULE.validate_status(changed)
        self.assertTrue(any("GH-242" in error for error in errors))

    def test_gh_242_status_drift_is_rejected(self) -> None:
        changed = copy.deepcopy(self.status)
        changed["post_audit_updates"]["gh_242"][
            "status"
        ] = "implemented_and_locally_tested_repository_boundary"
        self.assertTrue(
            any(
                "GH-242 repository boundary" in error
                for error in MODULE.validate_status(changed)
            )
        )

    def test_incomplete_gh_242_exact_main_evidence_is_rejected(self) -> None:
        changed = copy.deepcopy(self.status)
        del changed["post_audit_updates"]["gh_242"]["exact_main_runs"]["pages"]
        self.assertTrue(
            any(
                "GH-242 exact-main" in error
                for error in MODULE.validate_status(changed)
            )
        )

    def test_malformed_gh_242_merge_commit_is_rejected(self) -> None:
        changed = copy.deepcopy(self.status)
        changed["post_audit_updates"]["gh_242"]["merge_commit"] = "5cb132c"
        self.assertTrue(
            any(
                "GH-242 merge commit" in error
                for error in MODULE.validate_status(changed)
            )
        )

    def test_gh_242_public_surface_drift_is_rejected(self) -> None:
        root = SCRIPT.parents[1]
        merge_commit = self.status["post_audit_updates"]["gh_242"]["merge_commit"]
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            status_target = tmp_root / MODULE.STATUS_PATH
            status_target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(root / MODULE.STATUS_PATH, status_target)
            for relative in MODULE.PUBLIC_FILES:
                target = tmp_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(root / relative, target)
            drifted = tmp_root / "README.md"
            drifted.write_text(
                drifted.read_text(encoding="utf-8").replace(merge_commit, "0" * 40),
                encoding="utf-8",
            )
            errors = MODULE.verify(tmp_root)
            self.assertTrue(
                any(
                    "README.md" in error and "GH-242 exact-main" in error
                    for error in errors
                )
            )

    def test_gh_246_authority_or_production_drift_is_rejected(self) -> None:
        for field in (
            "signing_or_private_key_api",
            "external_membership_authority",
            "key_ownership_or_rotation_proven",
            "sybil_resistance_proven",
            "on_chain_attestation",
            "public_multihost_operation",
            "production_authority",
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.status)
                changed["post_audit_updates"]["gh_246"][field] = True
                self.assertTrue(
                    any("GH-246" in error for error in MODULE.validate_status(changed))
                )

    def test_incomplete_gh_246_exact_main_evidence_is_rejected(self) -> None:
        changed = copy.deepcopy(self.status)
        del changed["post_audit_updates"]["gh_246"]["exact_main_runs"]["pages"]
        self.assertTrue(
            any(
                "GH-246 exact-main run evidence" in error
                for error in MODULE.validate_status(changed)
            )
        )

    def test_malformed_gh_246_merge_commit_is_rejected(self) -> None:
        changed = copy.deepcopy(self.status)
        changed["post_audit_updates"]["gh_246"]["merge_commit"] = "f12e821"
        self.assertTrue(
            any(
                "GH-246 merge commit" in error
                for error in MODULE.validate_status(changed)
            )
        )

    def test_missing_gh_246_status_is_rejected(self) -> None:
        changed = copy.deepcopy(self.status)
        del changed["post_audit_updates"]["gh_246"]
        self.assertTrue(
            any("GH-246" in error for error in MODULE.validate_status(changed))
        )

    def test_malformed_gh_246_status_is_rejected_without_exception(self) -> None:
        for value in (None, [], "invalid", 246):
            with self.subTest(value=value):
                changed = copy.deepcopy(self.status)
                changed["post_audit_updates"]["gh_246"] = value
                self.assertTrue(
                    any(
                        "GH-246 machine status record must be an object" in error
                        for error in MODULE.validate_status(changed)
                    )
                )

    def test_gh_246_public_surface_drift_is_rejected(self) -> None:
        root = SCRIPT.parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            status_target = tmp_root / MODULE.STATUS_PATH
            status_target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(root / MODULE.STATUS_PATH, status_target)
            for relative in MODULE.PUBLIC_FILES:
                target = tmp_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(root / relative, target)
            drifted = tmp_root / "README.md"
            drifted.write_text(
                drifted.read_text(encoding="utf-8").replace(
                    "no signer/private-key path",
                    "signer/private-key boundary status",
                ),
                encoding="utf-8",
            )
            errors = MODULE.verify(tmp_root)
            self.assertTrue(
                any(
                    "README.md" in error and "GH-246 canonical" in error
                    for error in errors
                )
            )

    def test_gh_246_positive_authority_claim_is_rejected(self) -> None:
        root = SCRIPT.parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            status_target = tmp_root / MODULE.STATUS_PATH
            status_target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(root / MODULE.STATUS_PATH, status_target)
            for relative in MODULE.PUBLIC_FILES:
                target = tmp_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(root / relative, target)
            drifted = tmp_root / "README.md"
            drifted.write_text(
                drifted.read_text(encoding="utf-8")
                + "\nGH-246 provides external membership authority.\n",
                encoding="utf-8",
            )
            errors = MODULE.verify(tmp_root)
            self.assertTrue(
                any(
                    "README.md" in error
                    and "authority or production claim drift" in error
                    for error in errors
                )
            )

    def test_gh_246_enabling_authority_or_production_claim_is_rejected(self) -> None:
        root = SCRIPT.parents[1]
        for claim in (
            "GH-246 enables external membership authority.",
            "GH-246 enables production support.",
        ):
            with self.subTest(claim=claim), tempfile.TemporaryDirectory() as tmp:
                tmp_root = Path(tmp)
                status_target = tmp_root / MODULE.STATUS_PATH
                status_target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(root / MODULE.STATUS_PATH, status_target)
                for relative in MODULE.PUBLIC_FILES:
                    target = tmp_root / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy(root / relative, target)
                readme = tmp_root / "README.md"
                readme.write_text(
                    readme.read_text(encoding="utf-8") + f"\n{claim}\n",
                    encoding="utf-8",
                )
                errors = MODULE.verify(tmp_root)
                self.assertTrue(
                    any(
                        "README.md" in error
                        and "authority or production claim drift" in error
                        for error in errors
                    )
                )

    def test_banned_claims_return_categories_only(self) -> None:
        self.assertEqual(
            MODULE.find_banned_claims("PROM cannot be purchased."),
            ["prom-cannot-be-purchased"],
        )

    def test_stale_phi3_heuristic_claim_is_rejected(self) -> None:
        stale_claims = (
            "Phi-3 current implementation is a development-only heuristic/stub.",
            "Phi-3-mini 3.8B is planned. Current code is a development heuristic/stub.",
        )
        for claim in stale_claims:
            with self.subTest(claim=claim):
                self.assertEqual(
                    MODULE.find_banned_claims(claim),
                    ["stale-phi3-heuristic"],
                )

    def test_json_ld_validation(self) -> None:
        valid = '<script type="application/ld+json">{"name":"test"}</script>'
        invalid = '<script type="application/ld+json">{broken}</script>'
        self.assertEqual(MODULE.validate_json_ld(valid), [])
        self.assertEqual(MODULE.validate_json_ld(invalid), ["invalid JSON-LD block 1"])


if __name__ == "__main__":
    unittest.main()
