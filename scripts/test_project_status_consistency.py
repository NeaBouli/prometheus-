#!/usr/bin/env python3
"""Regression tests for the project-status consistency gate."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("verify_project_status_consistency.py")
SPEC = importlib.util.spec_from_file_location("status_consistency", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class StatusConsistencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.documents = {
            "memory/TODO.md": "\n".join(
                (
                    "[x] [P0] GH-9 `ValidatorStakingH001` Canary",
                    "[x] [P1] Rust-Projekt initialisieren",
                    "[x] [P1] Kaspa RPC-Verbindung implementieren",
                    "Development-only Byte-Scanner",
                )
            ),
            "memory/CHECKPOINT.md": "non-promotable; Production false",
            "BACKLOG.md": "six state-contract deployments remain",
            "docs/agent-bridge/CODEX_BRIDGE.md": "Current task: GH-220",
        }

    def assert_rejected(self, path: str, marker: str) -> None:
        self.documents[path] += f"\n{marker}"
        self.assertTrue(MODULE.validate_documents(self.documents))

    def test_current_fixture_passes(self) -> None:
        self.assertEqual(MODULE.validate_documents(self.documents), [])

    def test_rejects_incomplete_h001_status(self) -> None:
        self.documents["memory/TODO.md"] = self.documents["memory/TODO.md"].replace(
            "[x] [P0] GH-9", "[!] [P0] GH-9"
        )
        self.assertTrue(MODULE.validate_documents(self.documents))

    def test_rejects_stale_checkpoint(self) -> None:
        self.assert_rejected("memory/CHECKPOINT.md", "GH-203/PR #204")

    def test_rejects_stale_backlog(self) -> None:
        self.assert_rejected(
            "BACKLOG.md", "Latest documented green baseline is exact main `db33f566"
        )

    def test_rejects_stale_bridge_task(self) -> None:
        self.assert_rejected(
            "docs/agent-bridge/CODEX_BRIDGE.md", "Current handoff: GH-117"
        )

    def test_allows_historical_bridge_task_beyond_header(self) -> None:
        self.documents["docs/agent-bridge/CODEX_BRIDGE.md"] = (
            "Current handoff: GH-220\n"
            + "\n".join(f"header filler {index}" for index in range(40))
            + "\nCurrent handoff: GH-117"
        )
        self.assertEqual(MODULE.validate_documents(self.documents), [])

    def test_requires_rollout_boundaries(self) -> None:
        self.documents["memory/CHECKPOINT.md"] = "H-001 complete"
        self.documents["BACKLOG.md"] = "Nothing remains"
        errors = MODULE.validate_documents(self.documents)
        self.assertGreaterEqual(len(errors), 2)


if __name__ == "__main__":
    unittest.main()
