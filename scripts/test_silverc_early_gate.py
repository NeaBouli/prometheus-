#!/usr/bin/env python3
"""Regression: every v2-refusing entrypoint rejects the draft before any input read.

Each refusing tool is run in-process with ``--bundle v2-draft``. Archive, input
and output helpers, plus file/tar/temp primitives, are patched to fail if
called; the tool must raise the bundle refusal without reaching any of them and
without creating output. A v1 control proves the patched helpers are the real
first read for each tool. No compiler, network or wallet needed.
"""

from __future__ import annotations

import builtins
import importlib
import shutil
import sys
import tarfile
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

REACHED = "INPUT_READ_REACHED"

# Module-level helpers that read inputs, extract archives or write outputs.
HELPERS = (
    "bundle_root_from_args",
    "validate_manifest",
    "load_json",
    "load_report_json",
    "validate_report",
    "ensure_public_file",
    "run",
    "write_json",
    "write_runbook",
    "write_snippet",
)


def required_inputs(root: Path, kind: str) -> dict[str, list[str]]:
    """Input arguments per tool, pointing at missing or malformed files."""
    if kind == "missing":
        f = str(root / "missing.json")
        d = str(root / "missing-dir")
        archive = str(root / "missing.tar.gz")
    else:
        bad = root / "malformed.json"
        bad.write_text("{not json", encoding="utf-8")
        bad_archive = root / "malformed.tar.gz"
        bad_archive.write_bytes(b"not a gzip archive")
        f, d, archive = str(bad), str(root), str(bad_archive)
    out = str(root / "out")
    common = ["--archive", archive]
    return {
        "build_metrics_oracle_operator_procedure": [
            *common,
            "--tx-request",
            f,
            "--summary-out",
            f"{out}/s.json",
        ],
        "build_silverc_deploy_operator_procedure": [
            *common,
            "--request-set",
            f,
            "--requests-dir",
            d,
            "--summary-out",
            f"{out}/s.json",
        ],
        "build_silverc_operator_receipts": [
            *common,
            "--request-set",
            f,
            "--requests-dir",
            d,
            "--orchestrator-results",
            f,
            "--operator-receipts-out",
            f"{out}/r.json",
        ],
        "stage_metrics_oracle_status": [
            *common,
            "--tx-request",
            f,
            "--tx-result",
            f,
            "--status-out",
            f"{out}/s.json",
        ],
        "stage_silverc_deployment_status": [
            *common,
            "--operator-receipts",
            f,
            "--status-out",
            f"{out}/s.json",
        ],
        "verify_metrics_oracle_tx_evidence": [
            *common,
            "--tx-request",
            f,
            "--tx-result",
            f,
            "--evidence",
            f,
            "--summary-out",
            f"{out}/s.json",
        ],
        "verify_metrics_oracle_tx_result": [
            *common,
            "--tx-request",
            f,
            "--tx-result",
            f,
            "--summary-out",
            f"{out}/s.json",
        ],
        "verify_silverc_deploy_receipts": [
            *common,
            "--receipts",
            f,
            "--summary-out",
            f"{out}/s.json",
        ],
        "verify_silverc_deploy_receipt_evidence": [
            *common,
            "--receipts",
            f,
            "--evidence",
            f,
            "--summary-out",
            f"{out}/s.json",
        ],
        "build_silverc_operator_handoff": [
            *common,
            "--out-dir",
            out,
            "--network",
            "testnet",
            "--rpc-url",
            "kaspa-resolver://public",
            "--deployer-address",
            "kaspatest:qptestpreflight000000000000000000000000000000000",
            "--metrics-oracle-pubkey",
            "11" * 32,
        ],
        "build_metrics_oracle_tx_request": [
            *common,
            "--report",
            f,
            "--tx-request-out",
            f"{out}/t.json",
        ],
    }


def fail(*_args: Any, **_kwargs: Any) -> Any:
    raise AssertionError(REACHED)


class EarlyGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="prometheus-early-gate."))
        self.addCleanup(shutil.rmtree, self.root)

    def run_tool(
        self, tool: str, bundle: str, argv: list[str], block_primitives: bool
    ) -> None:
        module = importlib.import_module(tool)
        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    sys, "argv", [f"{tool}.py", "--bundle", bundle, *argv]
                )
            )
            for name in HELPERS:
                if hasattr(module, name):
                    stack.enter_context(
                        mock.patch.object(module, name, side_effect=fail)
                    )
            if block_primitives:
                for target, attr in (
                    (builtins, "open"),
                    (Path, "open"),
                    (Path, "read_text"),
                    (Path, "read_bytes"),
                    (Path, "write_text"),
                    (Path, "write_bytes"),
                    (Path, "mkdir"),
                    (tarfile, "open"),
                    (tempfile, "mkdtemp"),
                    (tempfile, "TemporaryDirectory"),
                    (shutil, "copy2"),
                    (shutil, "copyfile"),
                ):
                    stack.enter_context(
                        mock.patch.object(target, attr, side_effect=fail)
                    )
            module.main()

    def test_v2_refused_before_any_input_read(self) -> None:
        for kind in ("missing", "malformed"):
            root = self.root / kind
            root.mkdir()
            for tool, argv in required_inputs(root, kind).items():
                with self.subTest(tool=tool, inputs=kind):
                    with self.assertRaisesRegex(ValueError, "non-promotable draft"):
                        self.run_tool(tool, "v2-draft", argv, block_primitives=True)
                    self.assertFalse((root / "out").exists(), f"{tool} created output")

    def test_v1_control_reaches_input_helpers(self) -> None:
        # Proves the patched helpers sit on each tool's real first read path.
        for tool, argv in required_inputs(self.root, "missing").items():
            with self.subTest(tool=tool):
                with self.assertRaisesRegex(AssertionError, REACHED):
                    self.run_tool(tool, "h001-v1", argv, block_primitives=False)
                self.assertFalse((self.root / "out").exists(), f"{tool} created output")


if __name__ == "__main__":
    unittest.main()
