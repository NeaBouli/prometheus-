#!/usr/bin/env python3
"""Fail-closed reproducibility gate for the Guardian Python dependencies.

Checks that modules/guardian-node/requirements.txt pins every direct
dependency exactly, that requirements-lock.txt is a fully hash-pinned closure
containing each direct pin at the same version, and that the yara-x pin equals
the engine version enforced at runtime. Offline only; standard library only.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GUARDIAN = Path("modules/guardian-node")
REQUIREMENTS = GUARDIAN / "requirements.txt"
LOCK = GUARDIAN / "requirements-lock.txt"
YARA_QUALITY = GUARDIAN / "jaeger/yara_semantic_quality.py"

REGENERATE_COMMAND = (
    "uv pip compile requirements.txt --universal --python-version 3.11 "
    "--generate-hashes --no-emit-index-url --no-header -o requirements-lock.txt"
)
MAX_FILE_BYTES = 256 * 1024
NAME_RE = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
VERSION_RE = r"[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc|\.post|\.dev)[0-9]+)*"
DIRECT_RE = re.compile(rf"(?P<name>{NAME_RE})==(?P<version>{VERSION_RE})")
LOCK_ENTRY_RE = re.compile(
    rf"(?P<name>{NAME_RE})==(?P<version>{VERSION_RE})"
    r"(?: ; (?P<marker>[A-Za-z0-9_ .'<>=!\"-]+))? \\"
)
HASH_RE = re.compile(r"--hash=sha256:[0-9a-f]{64}(?P<cont> \\)?")
YARA_PIN_RE = re.compile(r'^PINNED_YARA_X_VERSION = "(?P<version>[^"]+)"$', re.M)


@dataclass(frozen=True)
class LockEntry:
    version: str
    hashes: int


def normalize(name: str) -> str:
    """PEP 503 name normalization."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _read(path: Path, label: str, errors: list[str]) -> str | None:
    try:
        if path.is_symlink():
            errors.append(f"{label}: symlink rejected")
            return None
        data = path.read_bytes()
    except FileNotFoundError:
        errors.append(f"{label}: file missing")
        return None
    except OSError:
        errors.append(f"{label}: unreadable")
        return None
    if len(data) > MAX_FILE_BYTES:
        errors.append(f"{label}: file too large")
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        errors.append(f"{label}: not UTF-8")
        return None


def parse_direct(text: str, errors: list[str]) -> dict[str, str]:
    pins: dict[str, str] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = DIRECT_RE.fullmatch(line)
        if match is None:
            errors.append(f"requirements.txt:{number}: not an exact name==version pin")
            continue
        name = normalize(match["name"])
        if name in pins:
            errors.append(f"requirements.txt:{number}: duplicate {name}")
            continue
        pins[name] = match["version"]
    if not pins:
        errors.append("requirements.txt: no pins")
    return pins


def parse_lock(text: str, errors: list[str]) -> dict[str, LockEntry]:
    entries: dict[str, LockEntry] = {}
    lines = text.splitlines()
    if REGENERATE_COMMAND not in text:
        errors.append("requirements-lock.txt: regenerate command header missing")
    current: str | None = None
    version = ""
    hashes = 0
    expect_hash = False

    def close() -> None:
        if current is None:
            return
        if hashes == 0:
            errors.append(f"requirements-lock.txt: {current} has no sha256 hash")
        entries[current] = LockEntry(version, hashes)

    for number, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if expect_hash:
            match = HASH_RE.fullmatch(stripped)
            if match is None or not raw.startswith("    "):
                errors.append(f"requirements-lock.txt:{number}: expected hash line")
                expect_hash = False
                continue
            hashes += 1
            expect_hash = match["cont"] is not None
            continue
        if not stripped or stripped.startswith("#"):
            continue
        if raw[0].isspace():
            errors.append(f"requirements-lock.txt:{number}: unexpected indented line")
            continue
        match = LOCK_ENTRY_RE.fullmatch(stripped)
        if match is None:
            errors.append(f"requirements-lock.txt:{number}: unsupported line")
            continue
        close()
        name = normalize(match["name"])
        if name in entries:
            errors.append(f"requirements-lock.txt:{number}: duplicate {name}")
            current = None
            expect_hash = True
            hashes = 0
            continue
        current, version, hashes, expect_hash = name, match["version"], 0, True
    if expect_hash:
        errors.append("requirements-lock.txt: truncated hash continuation")
    close()
    return entries


def verify(root: Path) -> tuple[list[str], str]:
    errors: list[str] = []
    direct_text = _read(root / REQUIREMENTS, "requirements.txt", errors)
    lock_text = _read(root / LOCK, "requirements-lock.txt", errors)
    yara_text = _read(root / YARA_QUALITY, "yara_semantic_quality.py", errors)
    direct = parse_direct(direct_text, errors) if direct_text is not None else {}
    lock = parse_lock(lock_text, errors) if lock_text is not None else {}
    if direct_text is not None and lock_text is not None:
        for name, version in sorted(direct.items()):
            entry = lock.get(name)
            if entry is None:
                errors.append(f"lock: direct dependency {name} missing")
            elif entry.version != version:
                errors.append(f"lock: {name} version differs from requirements.txt")
    if yara_text is not None and direct_text is not None:
        yara_pins = YARA_PIN_RE.findall(yara_text)
        if len(yara_pins) != 1:
            errors.append("yara-x: runtime pin constant not found exactly once")
        elif direct.get("yara-x") != yara_pins[0]:
            errors.append("yara-x: requirements pin differs from runtime pin")
    summary = f"({len(direct)} direct, {len(lock)} locked)"
    return sorted(set(errors)), summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify Guardian Python dependency pins and lock."
    )
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)
    errors, summary = verify(args.repo_root)
    if errors:
        print("guardian python deps: FAIL", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"guardian python deps: OK {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
