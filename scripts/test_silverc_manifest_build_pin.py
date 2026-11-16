#!/usr/bin/env python3
"""Build-lock and bundle-manifest pin tests for the SilverC release scripts."""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import preflight_silverc_deploy as pf  # noqa: E402
import silverc_bundles as bundles  # noqa: E402
import smoke_silverc_artifacts as smoke  # noqa: E402
import verify_silverc_h001 as vh  # noqa: E402

PIN = vh.DEFAULT_SILVERSCRIPT_REF
OTHER = "0" * 40


def completed(cmd: list[str], stdout: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")


class TempDirTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name).resolve()


class CargoLockedTest(TempDirTest):
    def make_silverc(self) -> Path:
        silverc = self.tmp / "target" / "debug" / "silverc"
        silverc.parent.mkdir(parents=True)
        silverc.write_text("stale\n")
        return silverc

    def test_real_workspace_pin_matches_default(self) -> None:
        self.assertEqual(vh.workspace_silverscript_rev(), PIN)

    def test_smoke_build_uses_locked(self) -> None:
        self.make_silverc()
        calls: list[list[str]] = []

        def fake_run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
            calls.append(cmd)
            return completed(cmd)

        with mock.patch.object(smoke, "run", side_effect=fake_run):
            smoke.build_silverc(self.tmp)
        self.assertEqual(calls, [["cargo", "build", "--locked", "-p", "silverscript-lang", "--bin", "silverc"]])

    def test_preflight_rebuilds_even_when_binary_exists(self) -> None:
        stale_silverc = self.make_silverc()
        order: list[str] = []
        calls: list[list[str]] = []
        isolated_target: Path | None = None

        def fake_run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
            nonlocal isolated_target
            calls.append(cmd)
            order.append(cmd[0] if cmd[0] == "cargo" else "silverc")
            if cmd[:2] == ["cargo", "build"]:
                isolated_target = Path(cmd[cmd.index("--target-dir") + 1])
                binary = isolated_target / "debug" / "silverc"
                binary.parent.mkdir(parents=True)
                binary.write_text("isolated\n")
            if cmd[:2] == ["cargo", "metadata"]:
                return completed(cmd, json.dumps({"packages": []}))
            return completed(cmd, "Usage: silverc [OPTIONS]\n")

        with (
            mock.patch.object(pf, "ensure_silverscript_repo", side_effect=lambda p, r: order.append("verify")),
            mock.patch.object(pf, "run", side_effect=fake_run),
        ):
            status = pf.inspect_silverc(self.tmp, PIN)

        self.assertEqual(calls[0][:4], ["cargo", "build", "--locked", "--target-dir"])
        self.assertIsNotNone(isolated_target)
        assert isolated_target is not None
        self.assertNotEqual(Path(calls[1][0]), stale_silverc)
        self.assertFalse(isolated_target.exists())
        self.assertEqual(order[:2], ["verify", "cargo"])
        self.assertFalse(status.has_deploy_command)
        self.assertEqual(status.silverc_path, "<isolated-target>/debug/silverc")

    def test_preflight_does_not_build_when_checkout_verification_fails(self) -> None:
        with (
            mock.patch.object(
                pf, "ensure_silverscript_repo", side_effect=vh.SilverscriptCheckoutError("rejected")
            ),
            mock.patch.object(pf, "run") as run,
        ):
            with self.assertRaises(vh.SilverscriptCheckoutError):
                pf.inspect_silverc(self.tmp, PIN)
        run.assert_not_called()

    def test_preflight_missing_binary_after_build_fails_without_path_leak(self) -> None:
        with (
            mock.patch.object(pf, "ensure_silverscript_repo"),
            mock.patch.object(pf, "run", side_effect=lambda cmd, cwd: completed(cmd)),
        ):
            with self.assertRaises(FileNotFoundError) as ctx:
                pf.inspect_silverc(self.tmp, PIN)
        self.assertNotIn(str(self.tmp), str(ctx.exception))

    def test_verify_probe_test_uses_locked(self) -> None:
        (self.tmp / "silverscript-lang" / "tests").mkdir(parents=True)
        calls: list[list[str]] = []
        with (
            mock.patch.dict(os.environ, {"SILVERSCRIPT_REPO": str(self.tmp), "SILVERSCRIPT_REF": PIN}),
            mock.patch.object(vh, "ensure_silverscript_repo"),
            mock.patch.object(vh, "require_clean_tree"),
            mock.patch.object(vh, "run", side_effect=lambda cmd, cwd, env=None: calls.append(cmd)),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(vh.main(), 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][:3], ["cargo", "test", "--locked"])


class ManifestPinTest(TempDirTest):
    BUNDLE = bundles.get_bundle(bundles.V2_DRAFT)

    def manifest(self, **overrides: Any) -> dict[str, Any]:
        data: dict[str, Any] = {
            "schema_version": 1,
            "silverscript_ref": PIN,
            "silverscript_commit": PIN,
            "fixture_count": len(smoke.FIXTURES),
            "fixtures": [
                {"contract_name": fixture.contract_name, "artifact_file": f"{fixture.contract_name}.json"}
                for fixture in smoke.FIXTURES
            ],
        }
        data.update(overrides)
        for key in [key for key, value in data.items() if value is None]:
            del data[key]
        return data

    def write(self, data: dict[str, Any]) -> Path:
        path = self.tmp / smoke.MANIFEST_NAME
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def assert_preflight_rejects(self, data: dict[str, Any], expected: str, message: str) -> None:
        self.write(data)
        with mock.patch.object(pf, "validate_manifest_entry") as entry:
            with self.assertRaisesRegex(ValueError, message):
                pf.validate_manifest(self.tmp, expected, self.BUNDLE)
        entry.assert_not_called()

    def test_preflight_accepts_ref_and_commit_equal_to_pin(self) -> None:
        self.write(self.manifest())
        with mock.patch.object(pf, "validate_manifest_entry") as entry, mock.patch.object(
            pf, "require_manifest_pin"
        ) as pin:
            manifest = pf.validate_manifest(self.tmp, PIN, self.BUNDLE)
        self.assertEqual(manifest["silverscript_commit"], PIN)
        self.assertEqual(entry.call_count, len(smoke.FIXTURES))
        pin.assert_called_once_with(self.BUNDLE, manifest)

    def test_preflight_rejects_pinned_ref_with_unpinned_manifest_hash(self) -> None:
        self.write(self.manifest())
        with mock.patch.object(pf, "validate_manifest_entry"):
            with self.assertRaisesRegex(ValueError, "manifest"):
                pf.validate_manifest(self.tmp, PIN, self.BUNDLE)

    def test_preflight_rejects_commit_mismatch(self) -> None:
        self.assert_preflight_rejects(self.manifest(silverscript_commit=OTHER), PIN, "unexpected silverscript_commit")

    def test_preflight_rejects_missing_commit(self) -> None:
        self.assert_preflight_rejects(self.manifest(silverscript_commit=None), PIN, "unexpected silverscript_commit")

    def test_preflight_rejects_ref_mismatch(self) -> None:
        self.assert_preflight_rejects(self.manifest(silverscript_ref=OTHER), PIN, "unexpected silverscript_ref")

    def test_preflight_rejects_expected_ref_off_pin_even_if_manifest_agrees(self) -> None:
        data = self.manifest(silverscript_ref=OTHER, silverscript_commit=OTHER)
        self.assert_preflight_rejects(data, OTHER, "expected silverscript ref does not match the workspace pin")

    def test_preflight_rejection_does_not_echo_manifest_values(self) -> None:
        self.write(self.manifest(silverscript_commit="attacker-controlled-value"))
        with self.assertRaises(ValueError) as ctx:
            pf.validate_manifest(self.tmp, PIN, self.BUNDLE)
        self.assertNotIn("attacker-controlled-value", str(ctx.exception))

    def test_smoke_rejects_commit_mismatch(self) -> None:
        path = self.write(self.manifest(silverscript_commit=OTHER))
        with self.assertRaisesRegex(ValueError, "silverscript_commit does not match the workspace pin"):
            smoke.validate_manifest(path, self.tmp, self.BUNDLE)

    def test_smoke_rejects_ref_mismatch(self) -> None:
        path = self.write(self.manifest(silverscript_ref=OTHER))
        with self.assertRaisesRegex(ValueError, "silverscript_ref does not match the workspace pin"):
            smoke.validate_manifest(path, self.tmp, self.BUNDLE)

    def test_smoke_pinned_manifest_proceeds_to_artifact_checks(self) -> None:
        path = self.write(self.manifest())
        with self.assertRaises(FileNotFoundError):
            smoke.validate_manifest(path, self.tmp, self.BUNDLE)


if __name__ == "__main__":
    unittest.main()
