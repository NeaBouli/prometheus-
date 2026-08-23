#!/usr/bin/env python3
"""Fail CI when canonical project-status files regress to known stale claims."""

from __future__ import annotations

import sys
from pathlib import Path


def validate_documents(documents: dict[str, str]) -> list[str]:
    errors: list[str] = []

    todo = documents["memory/TODO.md"]
    checkpoint = documents["memory/CHECKPOINT.md"]
    backlog = documents["BACKLOG.md"]
    bridge = documents["docs/agent-bridge/CODEX_BRIDGE.md"]
    bridge_header = "\n".join(bridge.splitlines()[:40])

    required_todo_markers = {
        "H-001 canary completion": "[x] [P0] GH-9 `ValidatorStakingH001` Canary",
        "client Rust foundation": "[x] [P1] Rust-Projekt initialisieren",
        "client RPC foundation": "[x] [P1] Kaspa RPC-Verbindung implementieren",
        "client scanner boundary": "Development-only Byte-Scanner",
    }
    for label, marker in required_todo_markers.items():
        if marker not in todo:
            errors.append(f"TODO is missing the current {label} marker")

    stale_markers = {
        "CHECKPOINT": (checkpoint, "GH-203/PR #204"),
        "BACKLOG": (backlog, "Latest documented green baseline is exact main `db33f566"),
        "Bridge header": (bridge_header, "Current handoff: GH-117"),
        "Bridge header baseline": (
            bridge_header,
            "Latest verified product/public baseline is GH-117",
        ),
    }
    for label, (content, marker) in stale_markers.items():
        if marker in content:
            errors.append(f"{label} still contains stale current-state marker: {marker}")

    if "non-promotable" not in checkpoint or "Production false" not in checkpoint:
        errors.append("CHECKPOINT must retain the H-001 non-promotable/production-false boundary")
    if "six state-contract deployments" not in backlog:
        errors.append("BACKLOG must retain the remaining six state-contract deployment gate")

    return errors


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    paths = (
        "memory/TODO.md",
        "memory/CHECKPOINT.md",
        "BACKLOG.md",
        "docs/agent-bridge/CODEX_BRIDGE.md",
    )
    documents = {
        path: (repo_root / path).read_text(encoding="utf-8") for path in paths
    }
    errors = validate_documents(documents)
    if errors:
        print("Project status consistency check failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("Project status consistency check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
