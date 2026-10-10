#!/usr/bin/env python3
"""Unit tests for the closed silverc bundle registry (no compiler needed)."""

from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import silverc_bundles as bundles  # noqa: E402

ROOT = bundles.ROOT
EVIDENCE = (
    ROOT / "docs/evidence/gh-9-h001-public-evidence-2026-08-12.json",
    ROOT / "docs/evidence/gh-9-h001-operator-receipts-2026-08-12.json",
)
DEPLOYER_LIB = ROOT / "modules/silverc-deployer/src/lib.rs"


def evidence_manifest_hashes() -> set[str]:
    found: set[str] = set()

    def walk(value: object) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "full_bundle_manifest_sha256" and isinstance(item, str):
                    found.add(item)
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    for path in EVIDENCE:
        walk(json.loads(path.read_text(encoding="utf-8")))
    return found


class BundleRegistryTest(unittest.TestCase):
    def test_unknown_bundle_rejected(self) -> None:
        for bad in ("", "h001", "v2", "H001-V1", "latest"):
            with self.subTest(bundle=bad), self.assertRaises(ValueError):
                bundles.get_bundle(bad)

    def test_registry_identities(self) -> None:
        v1 = bundles.get_bundle(bundles.H001_V1)
        v2 = bundles.get_bundle(bundles.V2_DRAFT)
        self.assertTrue(v1.promotable)
        self.assertFalse(v2.promotable)
        self.assertEqual(
            v1.profiles, {bundles.FULL_PROFILE, bundles.H001_CANARY_PROFILE}
        )
        self.assertEqual(v2.profiles, {bundles.FULL_PROFILE})
        self.assertNotEqual(v1.manifest_sha256, v2.manifest_sha256)
        self.assertEqual(
            [f.contract_name for f in v1.fixtures],
            [f.contract_name for f in v2.fixtures],
        )

    def test_v1_pin_matches_historical_evidence(self) -> None:
        self.assertEqual(evidence_manifest_hashes(), {bundles.H001_V1_MANIFEST_SHA256})

    def test_rust_deployer_pins_stay_on_v1(self) -> None:
        text = DEPLOYER_LIB.read_text(encoding="utf-8")
        pins = re.findall(r'MANIFEST_SHA256: &str =\s*"([0-9a-f]{64})"', text)
        self.assertEqual(pins, [bundles.H001_V1_MANIFEST_SHA256])
        self.assertNotIn(bundles.V2_DRAFT_MANIFEST_SHA256, text)

    def test_frozen_manifest_and_sources_are_consistent(self) -> None:
        v1 = bundles.get_bundle(bundles.H001_V1)
        manifest = json.loads(
            (bundles.H001_V1_DIR / "manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            bundles.canonical_manifest_sha256(manifest), bundles.H001_V1_MANIFEST_SHA256
        )
        for entry in manifest["fixtures"]:
            source = v1.source_path(entry["source_file"])
            self.assertTrue(source.is_file(), source)

    def test_source_path_rejects_foreign_or_unknown_paths(self) -> None:
        v1 = bundles.get_bundle(bundles.H001_V1)
        for bad in (
            "modules/contracts/silverc/Unknown.sil",
            "../modules/contracts/silverc/ValidatorStakingH001.sil",
            "modules/contracts/ValidatorStaking.ss",
            "modules/contracts/silverc/bundles/h001-v1/sources/ValidatorStakingH001.sil",
        ):
            with self.subTest(path=bad), self.assertRaises(ValueError):
                v1.source_path(bad)

    def test_profile_and_promotion_gates(self) -> None:
        v2 = bundles.get_bundle(bundles.V2_DRAFT)
        with self.assertRaises(ValueError):
            bundles.require_profile(v2, bundles.H001_CANARY_PROFILE)
        with self.assertRaises(ValueError):
            bundles.require_promotable(v2, "receipts")
        v1 = bundles.get_bundle(bundles.H001_V1)
        bundles.require_profile(v1, bundles.H001_CANARY_PROFILE)
        bundles.require_promotable(v1, "receipts")

    def test_manifest_pin_rejects_any_change(self) -> None:
        manifest = json.loads(
            (bundles.H001_V1_DIR / "manifest.json").read_text(encoding="utf-8")
        )
        v1 = bundles.get_bundle(bundles.H001_V1)
        bundles.require_manifest_pin(v1, manifest)
        manifest["fixtures"][0]["script_len"] += 1
        with self.assertRaises(ValueError):
            bundles.require_manifest_pin(v1, manifest)
        v2 = bundles.get_bundle(bundles.V2_DRAFT)
        with self.assertRaises(ValueError):
            bundles.require_manifest_pin(
                v2,
                json.loads(
                    (bundles.H001_V1_DIR / "manifest.json").read_text(encoding="utf-8")
                ),
            )


class FrozenBundleTamperTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.copy = self.tmp / "h001-v1"
        shutil.copytree(bundles.H001_V1_DIR, self.copy)

    def load(self) -> bundles.Bundle:
        with mock.patch.object(bundles, "H001_V1_DIR", self.copy):
            return bundles.get_bundle(bundles.H001_V1)

    def test_untouched_copy_loads(self) -> None:
        self.assertEqual(self.load().bundle_id, bundles.H001_V1)

    def test_altered_source_rejected(self) -> None:
        source = self.copy / "sources" / "ValidatorStakingState.sil"
        source.write_text(source.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "was modified"):
            self.load()

    def test_altered_fixture_rejected(self) -> None:
        path = self.copy / "fixtures.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["fixtures"][0]["abi"].append("extra")
        path.write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(ValueError, "was modified"):
            self.load()

    def test_extra_or_missing_file_rejected(self) -> None:
        (self.copy / "sources" / "Extra.sil").write_text(
            "pragma silverscript ^0.1.0;\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(ValueError, "file set"):
            self.load()

    def test_altered_provenance_rejected(self) -> None:
        path = self.copy / "provenance.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["origin_commit"] = "0" * 40
        path.write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(ValueError, "provenance.json"):
            self.load()


if __name__ == "__main__":
    unittest.main()
