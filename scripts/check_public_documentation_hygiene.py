#!/usr/bin/env python3
"""Reject operational network and privileged-access data in tracked public docs."""

from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


PUBLIC_SUFFIXES = {".html", ".json", ".md", ".rst", ".toml", ".txt", ".yaml", ".yml"}
IPV4_PATTERN = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
PRIVILEGED_SSH_TARGET_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])(?:admin|deploy|root)@[A-Za-z0-9][A-Za-z0-9._-]*",
    re.IGNORECASE,
)
SSH_ALIAS_COMMAND_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])ssh[ \t]+[a-z][a-z0-9-]*(?=[\s`'\";]|$)"
)
AUTHENTICATION_DIAGNOSTIC_PATTERN = re.compile(
    r"permission denied\s*\(publickey\)", re.IGNORECASE
)
JUMP_HOST_TOPOLOGY_PATTERN = re.compile(r"\bProxyJump\b")
HOST_IDENTIFIER_PATTERN = re.compile(r"\bhost\s+`[A-Za-z0-9._-]+`", re.IGNORECASE)
PRIVILEGED_ACCOUNT_CONTEXT_PATTERN = re.compile(
    r"\b(?:as|user)\s+`?(?:admin|deploy|root)`?\b", re.IGNORECASE
)
DIRECT_HOST_REFERENCE_PATTERN = re.compile(
    r"\bdirect\s+[A-Z][A-Za-z0-9._-]*\s+(?:PATH|access|host)\b"
)
ALLOWED_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "0.0.0.0/32",
        "127.0.0.0/8",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
    )
)


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    category: str


def _is_allowed_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(address in network for network in ALLOWED_NETWORKS)


def inspect_text(path: str, text: str) -> list[Violation]:
    """Return redacted violations without retaining matched operational values."""
    violations: list[Violation] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if any(not _is_allowed_address(match.group(0)) for match in IPV4_PATTERN.finditer(line)):
            violations.append(Violation(path, line_number, "non-documentation IPv4 address"))
        if PRIVILEGED_SSH_TARGET_PATTERN.search(line):
            violations.append(Violation(path, line_number, "privileged SSH target"))
        if SSH_ALIAS_COMMAND_PATTERN.search(line):
            violations.append(Violation(path, line_number, "operational SSH alias command"))
        if AUTHENTICATION_DIAGNOSTIC_PATTERN.search(line):
            violations.append(Violation(path, line_number, "authentication diagnostic"))
        if JUMP_HOST_TOPOLOGY_PATTERN.search(line):
            violations.append(Violation(path, line_number, "jump-host topology"))
        if HOST_IDENTIFIER_PATTERN.search(line):
            violations.append(Violation(path, line_number, "operational host identifier"))
        if PRIVILEGED_ACCOUNT_CONTEXT_PATTERN.search(line):
            violations.append(Violation(path, line_number, "privileged account context"))
        if DIRECT_HOST_REFERENCE_PATTERN.search(line):
            violations.append(Violation(path, line_number, "direct host reference"))
    return violations


def tracked_public_files(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    paths = (Path(raw.decode("utf-8")) for raw in result.stdout.split(b"\0") if raw)
    return sorted(path for path in paths if path.suffix.lower() in PUBLIC_SUFFIXES)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    violations: list[Violation] = []
    for relative_path in tracked_public_files(root):
        text = (root / relative_path).read_text(encoding="utf-8")
        violations.extend(inspect_text(relative_path.as_posix(), text))

    if violations:
        print(f"Public documentation hygiene failed: {len(violations)} violation(s).")
        for violation in violations:
            print(f"- {violation.path}:{violation.line}: {violation.category}")
        print("Matched values are intentionally omitted; move operational data to a private runbook.")
        return 1

    print("Public documentation hygiene passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
