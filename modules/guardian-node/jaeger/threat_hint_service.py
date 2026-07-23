"""Operated owner-only service for the Prometheus ThreatHint verifier boundary."""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import stat
import sys
import time
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from jaeger.threat_hint_ingress import (
    DEFAULT_VERIFIER_TIMEOUT_SECONDS,
    Kip16Groth16Verifier,
    ThreatHintIngress,
    ThreatHintIngressError,
    ThreatHintIngressServer,
    ThreatHintReplayLedger,
    ThreatProofContext,
    UnavailableThreatProofVerifier,
)

CONFIG_SCHEMA_VERSION: Final[int] = 1
MAX_CONFIG_BYTES: Final[int] = 8_192
MAX_SERVICE_CONNECTIONS: Final[int] = 1_024
_ROOT_FIELDS = {
    "schema_version",
    "network_id",
    "socket_path",
    "ledger_path",
    "max_connections",
    "io_timeout_seconds",
    "verifier",
}
_KIP16_FIELDS = {
    "mode",
    "binary_path",
    "manifest_path",
    "expected_manifest_sha256",
    "timeout_seconds",
}


@dataclass(frozen=True)
class ThreatHintServiceConfig:
    """Validated service configuration with an explicit verifier mode."""

    network_id: str
    socket_path: Path
    ledger_path: Path
    max_connections: int
    io_timeout_seconds: float
    verifier_mode: str
    verifier_binary_path: Path | None = None
    verifier_manifest_path: Path | None = None
    verifier_manifest_sha256: str | None = None
    verifier_timeout_seconds: float = DEFAULT_VERIFIER_TIMEOUT_SECONDS


def load_service_config(path: Path) -> ThreatHintServiceConfig:
    """Load an exact-schema TOML config from an owner-only regular file."""
    config_path = _validate_owner_config(path)
    try:
        data = tomllib.loads(config_path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ThreatHintIngressError("ThreatHint service config is invalid") from exc
    if not isinstance(data, dict) or set(data) != _ROOT_FIELDS:
        raise ThreatHintIngressError("ThreatHint service config schema is invalid")
    if (
        isinstance(data["schema_version"], bool)
        or not isinstance(data["schema_version"], int)
        or data["schema_version"] != CONFIG_SCHEMA_VERSION
    ):
        raise ThreatHintIngressError("ThreatHint service config version is invalid")
    verifier = data["verifier"]
    if not isinstance(verifier, dict) or "mode" not in verifier:
        raise ThreatHintIngressError("ThreatHint verifier config is invalid")
    mode = verifier["mode"]
    if mode == "unavailable":
        if set(verifier) != {"mode"}:
            raise ThreatHintIngressError("unavailable verifier config is not closed")
        verifier_values: tuple[Path | None, Path | None, str | None, float] = (
            None,
            None,
            None,
            DEFAULT_VERIFIER_TIMEOUT_SECONDS,
        )
    elif mode == "kip16_groth16":
        if set(verifier) != _KIP16_FIELDS:
            raise ThreatHintIngressError("KIP-16 verifier config schema is invalid")
        timeout = _number(verifier["timeout_seconds"], "verifier timeout")
        verifier_values = (
            _path(verifier["binary_path"], "verifier binary path"),
            _path(verifier["manifest_path"], "verifier manifest path"),
            _string(verifier["expected_manifest_sha256"], "manifest anchor"),
            timeout,
        )
    else:
        raise ThreatHintIngressError("ThreatHint verifier mode is invalid")
    max_connections = data["max_connections"]
    if (
        isinstance(max_connections, bool)
        or not isinstance(max_connections, int)
        or not 1 <= max_connections <= MAX_SERVICE_CONNECTIONS
    ):
        raise ThreatHintIngressError("max_connections is outside the service bound")
    return ThreatHintServiceConfig(
        network_id=_string(data["network_id"], "network id"),
        socket_path=_path(data["socket_path"], "socket path"),
        ledger_path=_path(data["ledger_path"], "ledger path"),
        max_connections=max_connections,
        io_timeout_seconds=_number(data["io_timeout_seconds"], "I/O timeout"),
        verifier_mode=mode,
        verifier_binary_path=verifier_values[0],
        verifier_manifest_path=verifier_values[1],
        verifier_manifest_sha256=verifier_values[2],
        verifier_timeout_seconds=verifier_values[3],
    )


def build_service(
    config: ThreatHintServiceConfig,
    *,
    now_seconds: Callable[[], int] = lambda: int(time.time()),
) -> ThreatHintIngressServer:
    """Construct the server without starting network or background activity."""
    context = ThreatProofContext(config.network_id)
    if config.verifier_mode == "unavailable":
        verifier = UnavailableThreatProofVerifier()
    elif (
        config.verifier_mode == "kip16_groth16"
        and config.verifier_binary_path is not None
        and config.verifier_manifest_path is not None
        and config.verifier_manifest_sha256 is not None
    ):
        verifier = Kip16Groth16Verifier(
            config.verifier_binary_path,
            config.verifier_manifest_path,
            config.verifier_manifest_sha256,
            timeout_seconds=config.verifier_timeout_seconds,
        )
    else:
        raise ThreatHintIngressError("ThreatHint verifier configuration is incomplete")
    return ThreatHintIngressServer(
        config.socket_path,
        ThreatHintIngress(
            ThreatHintReplayLedger(config.ledger_path), verifier, context
        ),
        now_seconds=now_seconds,
        max_connections=config.max_connections,
        io_timeout_seconds=config.io_timeout_seconds,
    )


async def run_service(config: ThreatHintServiceConfig) -> None:
    """Run until SIGINT or SIGTERM and always remove the owned socket."""
    server = build_service(config)
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    watched = (signal.SIGINT, signal.SIGTERM)
    for watched_signal in watched:
        loop.add_signal_handler(watched_signal, stopped.set)
    try:
        await server.start()
        await stopped.wait()
    finally:
        await server.close()
        for watched_signal in watched:
            loop.remove_signal_handler(watched_signal)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prometheus ThreatHint verifier service"
    )
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args()
    try:
        config = load_service_config(args.config)
        asyncio.run(run_service(config))
    except (OSError, ThreatHintIngressError):
        print("ThreatHint verifier service failed closed", file=sys.stderr)
        return 1
    return 0


def _validate_owner_config(path: Path) -> Path:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise ThreatHintIngressError("ThreatHint service config path must be absolute")
    try:
        parent = path.parent.resolve(strict=True)
        parent_stat = parent.stat()
        current = path.lstat()
    except OSError as exc:
        raise ThreatHintIngressError(
            "ThreatHint service config is unavailable"
        ) from exc
    candidate = parent / path.name
    if (
        candidate != path
        or not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != os.getuid()
        or parent_stat.st_mode & 0o077
        or not stat.S_ISREG(current.st_mode)
        or current.st_uid != os.getuid()
        or current.st_mode & 0o077
        or current.st_mode & 0o7000
        or current.st_size == 0
        or current.st_size > MAX_CONFIG_BYTES
    ):
        raise ThreatHintIngressError("ThreatHint service config must be owner-only")
    return candidate


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ThreatHintIngressError(f"{label} must be a non-empty string")
    return value


def _path(value: object, label: str) -> Path:
    path = Path(_string(value, label))
    if (
        not path.is_absolute()
        or path.name in {"", ".", ".."}
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise ThreatHintIngressError(f"{label} must be an absolute canonical path")
    return path


def _number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ThreatHintIngressError(f"{label} must be numeric")
    return float(value)


if __name__ == "__main__":
    raise SystemExit(main())
