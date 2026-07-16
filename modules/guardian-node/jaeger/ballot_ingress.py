"""Owner-only local ingress for authenticated Guardian ballot bytes.

The libp2p carrier is intentionally untrusted by this boundary. It forwards one
bounded opaque frame; this module resolves a locally registered session and
delegates every protocol and authorization check to ``signed_ballots``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Callable
from typing import Final, Literal

from .ensemble import EnsembleCandidate, MembershipSnapshot
from .signed_ballots import (
    MAX_BALLOT_WIRE_BYTES,
    AuthenticatedBallotCollector,
    BallotReplayError,
    BallotSession,
    BallotTransportError,
    SignedGuardianBallot,
)

INGRESS_PROTOCOL_VERSION: Final[int] = 1
MAX_INGRESS_ACK_BYTES: Final[int] = 512
DEFAULT_IO_TIMEOUT_SECONDS: Final[float] = 5.0
DEFAULT_MAX_CONNECTIONS: Final[int] = 32
_FRAME_PREFIX_BYTES = 4
_LOWER_HEX_32 = re.compile(r"[0-9a-f]{64}")

IngressStatus = Literal["accepted", "duplicate", "rejected", "busy"]


class BallotIngressError(ValueError):
    """The local ingress configuration or frame is unsafe."""


@dataclass(frozen=True)
class BallotContext:
    """Locally trusted verification context for one committed session."""

    candidate: EnsembleCandidate
    snapshot: MembershipSnapshot
    session: BallotSession


@dataclass(frozen=True)
class IngressAck:
    """Small canonical result returned to the transport sidecar."""

    status: IngressStatus
    session_id: str
    payload_digest: str

    def to_wire(self) -> bytes:
        if not self._has_valid_identifiers():
            raise BallotIngressError("invalid ingress acknowledgement identifiers")
        payload = {
            "payload_digest": self.payload_digest,
            "protocol_version": INGRESS_PROTOCOL_VERSION,
            "session_id": self.session_id,
            "status": self.status,
        }
        wire = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        if len(wire) > MAX_INGRESS_ACK_BYTES:
            raise BallotIngressError("ingress acknowledgement exceeds size limit")
        return wire

    @classmethod
    def from_wire(cls, wire: bytes) -> "IngressAck":
        if not 0 < len(wire) <= MAX_INGRESS_ACK_BYTES:
            raise BallotIngressError("invalid ingress acknowledgement size")
        try:
            payload = json.loads(wire, object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BallotIngressError("invalid ingress acknowledgement") from exc
        if not isinstance(payload, dict) or set(payload) != {
            "payload_digest",
            "protocol_version",
            "session_id",
            "status",
        }:
            raise BallotIngressError("invalid ingress acknowledgement schema")
        if payload["protocol_version"] != INGRESS_PROTOCOL_VERSION:
            raise BallotIngressError("unsupported ingress protocol version")
        status = payload["status"]
        if status not in {"accepted", "duplicate", "rejected", "busy"}:
            raise BallotIngressError("invalid ingress acknowledgement status")
        session_id = payload["session_id"]
        payload_digest = payload["payload_digest"]
        if not isinstance(session_id, str) or not isinstance(payload_digest, str):
            raise BallotIngressError("invalid ingress acknowledgement fields")
        ack = cls(status, session_id, payload_digest)
        if ack.to_wire() != wire:
            raise BallotIngressError("non-canonical ingress acknowledgement")
        return ack

    def _has_valid_identifiers(self) -> bool:
        session_valid = not self.session_id or bool(
            _LOWER_HEX_32.fullmatch(self.session_id)
        )
        digest_valid = not self.payload_digest or bool(
            _LOWER_HEX_32.fullmatch(self.payload_digest)
        )
        if not session_valid or not digest_valid:
            return False
        if self.status in {"accepted", "duplicate"}:
            return bool(self.session_id and self.payload_digest)
        if self.status == "busy":
            return not self.session_id and not self.payload_digest
        return True


class BallotIngress:
    """Resolve local sessions and invoke the existing authenticated collector."""

    def __init__(self, collector: AuthenticatedBallotCollector) -> None:
        self._collector = collector
        self._contexts: dict[str, BallotContext] = {}

    def register(self, context: BallotContext) -> None:
        session_id = context.session.session_id
        current = self._contexts.get(session_id)
        if current is not None and current != context:
            raise BallotIngressError("session id is already registered")
        self._contexts[session_id] = context

    def process(self, wire: bytes, now_ms: int) -> IngressAck:
        digest = hashlib.sha256(wire).hexdigest()
        if not 0 < len(wire) <= MAX_BALLOT_WIRE_BYTES:
            return IngressAck("rejected", "", digest)

        try:
            envelope = SignedGuardianBallot.from_wire(wire)
            context = self._contexts.get(envelope.session_id)
            if context is None:
                return IngressAck("rejected", envelope.session_id, digest)
            self._collector.accept_wire(
                wire,
                context.candidate,
                context.snapshot,
                context.session,
                now_ms,
            )
            return IngressAck("accepted", envelope.session_id, digest)
        except BallotReplayError:
            # Exact retransmission is idempotent. Equivocation remains rejected.
            if self._collector.contains_wire(envelope.session_id, wire):
                return IngressAck("duplicate", envelope.session_id, digest)
            return IngressAck("rejected", envelope.session_id, digest)
        except BallotTransportError:
            return IngressAck("rejected", "", digest)


class BallotIngressServer:  # pylint: disable=too-many-instance-attributes
    """Single-frame AF_UNIX server with bounded concurrency and deadlines."""

    def __init__(
        self,
        path: Path,
        ingress: BallotIngress,
        *,
        now_ms: Callable[[], int],
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        io_timeout_seconds: float = DEFAULT_IO_TIMEOUT_SECONDS,
    ) -> None:
        if max_connections < 1:
            raise BallotIngressError("max_connections must be positive")
        if not 0 < io_timeout_seconds <= 60:
            raise BallotIngressError("io timeout must be in (0, 60] seconds")
        self._path = _validate_socket_path(path)
        self._ingress = ingress
        self._now_ms = now_ms
        self._max_connections = max_connections
        self._io_timeout = io_timeout_seconds
        self._server: asyncio.AbstractServer | None = None
        self._active = 0
        self._active_lock = asyncio.Lock()
        self._socket_identity: tuple[int, int] | None = None

    async def start(self) -> None:
        if self._server is not None:
            raise BallotIngressError("ingress server is already running")
        try:
            self._server = await asyncio.start_unix_server(
                self._handle_connection, path=str(self._path)
            )
            path_stat = self._path.lstat()
            if not stat.S_ISSOCK(path_stat.st_mode):
                raise BallotIngressError("ingress path is not a Unix socket")
            self._socket_identity = (path_stat.st_dev, path_stat.st_ino)
            os.chmod(self._path, 0o600)
        except Exception:
            await self.close()
            raise

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        _unlink_owned_socket(self._path, self._socket_identity)
        self._socket_identity = None

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        admitted = False
        try:
            async with self._active_lock:
                if self._active < self._max_connections:
                    self._active += 1
                    admitted = True
            if not admitted:
                await asyncio.wait_for(
                    _write_frame(writer, IngressAck("busy", "", "").to_wire()),
                    self._io_timeout,
                )
                return

            prefix = await asyncio.wait_for(
                reader.readexactly(_FRAME_PREFIX_BYTES), self._io_timeout
            )
            frame_size = int.from_bytes(prefix, "big")
            if not 0 < frame_size <= MAX_BALLOT_WIRE_BYTES:
                await _write_frame(writer, IngressAck("rejected", "", "").to_wire())
                return
            wire = await asyncio.wait_for(
                reader.readexactly(frame_size), self._io_timeout
            )
            ack = await asyncio.wait_for(
                asyncio.to_thread(self._ingress.process, wire, self._now_ms()),
                self._io_timeout,
            )
            await asyncio.wait_for(
                _write_frame(writer, ack.to_wire()), self._io_timeout
            )
        except (asyncio.IncompleteReadError, TimeoutError, ConnectionError):
            pass
        finally:
            if admitted:
                async with self._active_lock:
                    self._active -= 1
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass


async def submit_to_ingress(
    path: Path,
    wire: bytes,
    *,
    timeout_seconds: float = DEFAULT_IO_TIMEOUT_SECONDS,
) -> IngressAck:
    """Submit one exact ballot frame to a local Guardian ingress."""
    if not 0 < len(wire) <= MAX_BALLOT_WIRE_BYTES:
        raise BallotIngressError("invalid outbound ballot size")
    reader, writer = await asyncio.wait_for(
        asyncio.open_unix_connection(str(path)), timeout_seconds
    )
    try:
        await asyncio.wait_for(_write_frame(writer, wire), timeout_seconds)
        prefix = await asyncio.wait_for(
            reader.readexactly(_FRAME_PREFIX_BYTES), timeout_seconds
        )
        ack_size = int.from_bytes(prefix, "big")
        if not 0 < ack_size <= MAX_INGRESS_ACK_BYTES:
            raise BallotIngressError("invalid ingress acknowledgement size")
        ack_wire = await asyncio.wait_for(reader.readexactly(ack_size), timeout_seconds)
        return IngressAck.from_wire(ack_wire)
    finally:
        writer.close()
        await writer.wait_closed()


async def _write_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    writer.write(len(payload).to_bytes(_FRAME_PREFIX_BYTES, "big") + payload)
    await writer.drain()


def _validate_socket_path(path: Path) -> Path:
    resolved_parent = path.parent.resolve(strict=True)
    parent_stat = resolved_parent.stat()
    if not stat.S_ISDIR(parent_stat.st_mode):
        raise BallotIngressError("ingress parent must be a directory")
    if parent_stat.st_uid != os.getuid() or parent_stat.st_mode & 0o077:
        raise BallotIngressError("ingress parent must be owner-controlled")
    candidate = resolved_parent / path.name
    if candidate.exists() or candidate.is_symlink():
        raise BallotIngressError("ingress socket path already exists")
    if len(os.fsencode(candidate)) >= 100:
        raise BallotIngressError("ingress socket path is too long")
    return candidate


def _unlink_owned_socket(path: Path, expected_identity: tuple[int, int] | None) -> None:
    if expected_identity is None:
        return
    try:
        current = path.lstat()
    except FileNotFoundError:
        return
    if (
        stat.S_ISSOCK(current.st_mode)
        and (current.st_dev, current.st_ino) == expected_identity
    ):
        path.unlink()


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BallotIngressError("duplicate acknowledgement field")
        result[key] = value
    return result
