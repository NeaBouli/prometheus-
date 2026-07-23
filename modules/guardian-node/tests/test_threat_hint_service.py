"""Configuration tests for the operated ThreatHint verifier service."""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import pytest

from jaeger.threat_hint_ingress import ThreatHintIngressError
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


def test_kip16_mode_loads_only_exact_fields() -> None:
    directory = owner_only_directory()
    try:
        binary = directory / "verifier"
        binary.write_text("#!/bin/sh\nexit 3\n", encoding="ascii")
        os.chmod(binary, 0o700)
        manifest = directory / "relation-manifest.json"
        manifest.write_bytes(b"{}")
        os.chmod(manifest, 0o600)
        anchor = "11" * 32
        verifier = "\n".join(
            (
                'mode = "kip16_groth16"',
                f'binary_path = "{binary}"',
                f'manifest_path = "{manifest}"',
                f'expected_manifest_sha256 = "{anchor}"',
                "timeout_seconds = 1.5",
            )
        )
        config = load_service_config(write_config(directory, verifier))
        assert config.verifier_binary_path == binary
        assert config.verifier_timeout_seconds == 1.5
        assert build_service(config) is not None
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
        ).replace(str(directory / "threat-hint.sock"), "/tmp/../threat-hint.sock")
        clean.write_text(traversal, encoding="ascii")
        with pytest.raises(ThreatHintIngressError, match="canonical path"):
            load_service_config(clean)
        write_config(directory, 'mode = "unavailable"')
        os.chmod(directory / "service.toml", 0o644)
        with pytest.raises(ThreatHintIngressError, match="owner-only"):
            load_service_config(directory / "service.toml")
    finally:
        shutil.rmtree(directory)
