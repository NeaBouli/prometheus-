"""Configuration tests for the operated ThreatHint verifier service."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from jaeger import threat_hint_service
from jaeger.threat_hint_ingress import Kip16Groth16Verifier, ThreatHintIngressError
from jaeger.threat_hint_service import build_service, load_service_config


def owner_only_directory() -> Path:
    path = Path(tempfile.mkdtemp(prefix=".phs-", dir=Path.home())).resolve()
    os.chmod(path, 0o700)
    return path


def write_config(directory: Path, verifier: str, *, extra: str = "") -> Path:
    path = directory / "service.toml"
    socket_path = directory / "threat-hint.sock"
    ledger_path = directory / "replay.sqlite3"
    path.write_text(
        "\n".join(
            (
                "schema_version = 1",
                'network_id = "testnet-10"',
                f'socket_path = "{socket_path}"',
                f'ledger_path = "{ledger_path}"',
                "max_connections = 4",
                "io_timeout_seconds = 2.0",
                extra,
                "[verifier]",
                verifier,
                "",
            )
        ),
        encoding="ascii",
    )
    os.chmod(path, 0o600)
    return path


def test_unavailable_mode_builds_fail_closed_service() -> None:
    directory = owner_only_directory()
    try:
        config = load_service_config(write_config(directory, 'mode = "unavailable"'))
        assert config.verifier_mode == "unavailable"
        assert config.network_id == "testnet-10"
        assert build_service(config) is not None
    finally:
        shutil.rmtree(directory)


def kip16_fixture(directory: Path) -> tuple[Path, Path, str]:
    binary = directory / "verifier"
    binary.write_text("#!/bin/sh\nexit 3\n", encoding="ascii")
    os.chmod(binary, 0o700)
    manifest = directory / "relation-manifest.json"
    manifest.write_bytes(b"{}")
    os.chmod(manifest, 0o600)
    return binary, manifest, hashlib.sha256(binary.read_bytes()).hexdigest()


def kip16_verifier(binary: Path, manifest: Path, executable_anchor: str | None) -> str:
    lines = [
        'mode = "kip16_groth16"',
        f'binary_path = "{binary}"',
        f'manifest_path = "{manifest}"',
        f'expected_manifest_sha256 = "{"11" * 32}"',
        "timeout_seconds = 1.5",
    ]
    if executable_anchor is not None:
        lines.append(f"expected_executable_sha256 = {executable_anchor}")
    return "\n".join(lines)


def assert_redacted(
    exc: pytest.ExceptionInfo[ThreatHintIngressError], *values: str
) -> None:
    message = str(exc.value)
    for value in values:
        assert value not in message


def test_kip16_mode_loads_only_exact_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    directory = owner_only_directory()
    try:
        binary, manifest, digest = kip16_fixture(directory)
        config = load_service_config(
            write_config(directory, kip16_verifier(binary, manifest, f'"{digest}"'))
        )
        assert config.verifier_binary_path == binary
        assert config.verifier_executable_sha256 == digest
        assert config.verifier_timeout_seconds == 1.5
        seen: list[str] = []

        def pinned(*args: object, **kwargs: object) -> Kip16Groth16Verifier:
            anchor = kwargs["expected_executable_sha256"]
            assert isinstance(anchor, str)
            seen.append(anchor)
            return Kip16Groth16Verifier(*args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(threat_hint_service, "Kip16Groth16Verifier", pinned)
        assert build_service(config) is not None
        assert seen == [digest]
    finally:
        shutil.rmtree(directory)


def test_kip16_mode_requires_executable_anchor() -> None:
    directory = owner_only_directory()
    try:
        binary, manifest, digest = kip16_fixture(directory)
        missing = write_config(directory, kip16_verifier(binary, manifest, None))
        with pytest.raises(ThreatHintIngressError, match="schema") as exc:
            load_service_config(missing)
        assert_redacted(exc, str(directory), digest)
    finally:
        shutil.rmtree(directory)


@pytest.mark.parametrize(
    "anchor",
    (
        "UPPER",
        "SHORT",
        "LONG",
        "NONHEX",
        '""',
        "42",
        "true",
        '["00"]',
    ),
)
def test_kip16_mode_rejects_malformed_executable_anchor(anchor: str) -> None:
    directory = owner_only_directory()
    try:
        binary, manifest, digest = kip16_fixture(directory)
        value = {
            "UPPER": f'"{digest.upper()}"',
            "SHORT": f'"{digest[:-2]}"',
            "LONG": f'"{digest}00"',
            "NONHEX": f'"{"g" * 64}"',
        }.get(anchor, anchor)
        path = write_config(directory, kip16_verifier(binary, manifest, value))
        with pytest.raises(ThreatHintIngressError, match="executable anchor") as exc:
            load_service_config(path)
        assert_redacted(exc, str(directory), digest, digest.upper())
    finally:
        shutil.rmtree(directory)


def test_kip16_mode_rejects_wrong_executable_anchor_at_build() -> None:
    directory = owner_only_directory()
    try:
        binary, manifest, digest = kip16_fixture(directory)
        wrong = "0" * 64 if digest != "0" * 64 else "1" * 64
        config = load_service_config(
            write_config(directory, kip16_verifier(binary, manifest, f'"{wrong}"'))
        )
        with pytest.raises(ThreatHintIngressError, match="not trusted") as exc:
            build_service(config)
        assert_redacted(exc, str(directory), digest, wrong)
    finally:
        shutil.rmtree(directory)


def test_config_rejects_unknown_fields_and_unsafe_mode() -> None:
    directory = owner_only_directory()
    try:
        unknown = write_config(
            directory, 'mode = "unavailable"', extra='unexpected = "value"'
        )
        with pytest.raises(ThreatHintIngressError, match="schema"):
            load_service_config(unknown)
        clean = write_config(directory, 'mode = "unavailable"')
        boolean_version = clean.read_text(encoding="ascii").replace(
            "schema_version = 1", "schema_version = true"
        )
        clean.write_text(boolean_version, encoding="ascii")
        os.chmod(clean, 0o600)
        with pytest.raises(ThreatHintIngressError, match="version"):
            load_service_config(clean)
        oversized = boolean_version.replace(
            "schema_version = true", "schema_version = 1"
        ).replace("max_connections = 4", "max_connections = 1025")
        clean.write_text(oversized, encoding="ascii")
        with pytest.raises(ThreatHintIngressError, match="service bound"):
            load_service_config(clean)
        traversal = oversized.replace(
            "max_connections = 1025", "max_connections = 4"
        ).replace(
            str(directory / "threat-hint.sock"),
            str(directory / ".." / "threat-hint.sock"),
        )
        clean.write_text(traversal, encoding="ascii")
        with pytest.raises(ThreatHintIngressError, match="canonical path"):
            load_service_config(clean)
        write_config(directory, 'mode = "unavailable"')
        os.chmod(directory / "service.toml", 0o644)
        with pytest.raises(ThreatHintIngressError, match="owner-only"):
            load_service_config(directory / "service.toml")
    finally:
        shutil.rmtree(directory)
