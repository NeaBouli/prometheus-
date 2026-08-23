#!/usr/bin/env python3
"""Unit tests for the public claim consistency gate."""

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("verify_public_claim_consistency.py")
SPEC = importlib.util.spec_from_file_location("claim_consistency", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PublicClaimConsistencyTests(unittest.TestCase):
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
