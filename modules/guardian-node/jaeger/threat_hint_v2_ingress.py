"""Fail-closed owner-only local ThreatHint-v2 ingress boundary.

The ingress sits strictly below the ThreatHint-v2 promotion service and owns
the local AF_UNIX transport edge for canonical v2 transport payloads. The
fail-closed order is fixed:

1. The exact wire is parsed with ``ThreatHintV2TransportPayload`` against a
   separately trusted local network. An invalid transport frame never reaches
   the session resolver or the promotion service.
2. The payload report nonce is treated only as an UNTRUSTED session lookup
   key. It is resolved through an injected exact active-session resolver
   BEFORE promotion is called. An unknown session, a resolver mismatch, or a
   malformed resolver answer rejects the payload without calling promotion.
3. The current time is obtained only from an injected trusted callable. An
   unavailable or out-of-range trusted clock is a local failure (busy), never
   candidate data, and never reaches promotion.
4. Only then is ``ThreatHintV2PromotionService.promote`` called with the
   exact three original wires, the resolved nonce, and the trusted time.

Status mapping is stable: promotion success maps to ``accepted``, a busy
promotion (or an unavailable trusted side) maps to ``busy``, and replay or
any invalid candidate maps to ``rejected``. The acknowledgement contains
only the SHA-256 payload digest, ``protocol_version`` 2, and the status. It
never contains nested wires, the nonce, the approval, policy material, or any
promotion result.

The bounded owner-only AF_UNIX server accepts exactly one length-prefixed
frame per connection, capped at ``MAX_TRANSPORT_PAYLOAD_BYTES``. The socket
is created ``0600`` inside an owner-only ``0700`` parent, peer effective-uids
are required to match where the platform exposes them, connection count and
I/O are bounded, the response is the exact canonical acknowledgement frame,
and shutdown removes only the owned socket by captured device/inode identity.

This module supplies no configuration CLI and constructs no production
promotion service; wiring trusted material remains with the owner.
"""

# Exact built-in types are protocol requirements.
# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import socket
import stat
import struct
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, Optional, Protocol

from jaeger.observable_approval import UINT64_MAX
from jaeger.threat_hint_v2_promotion import (
    ThreatHintV2PromotionBusyError,
    ThreatHintV2PromotionError,
    ThreatHintV2PromotionReplayError,
    ThreatHintV2PromotionService,
    ThreatHintV2PromotionUnavailableError,
)
from jaeger.threat_hint_v2_transport import (
    MAX_TRANSPORT_PAYLOAD_BYTES,
    REPORT_NONCE_BYTES,
    ThreatHintV2TransportError,
    ThreatHintV2TransportPayload,
)
from jaeger.threat_observable import validate_network_id

THREAT_HINT_V2_PROTOCOL_VERSION: Final[int] = 2
MAX_V2_INGRESS_ACK_BYTES: Final[int] = 384
DEFAULT_IO_TIMEOUT_SECONDS: Final[float] = 5.0
DEFAULT_MAX_CONNECTIONS: Final[int] = 32

_FRAME_PREFIX_BYTES: Final[int] = 4
_LISTEN_BACKLOG: Final[int] = 16
_ZERO_DIGEST: Final[str] = "0" * 64
_LOWER_HEX_32 = re.compile(r"[0-9a-f]{64}")

ThreatHintV2IngressStatus = Literal["accepted", "rejected", "busy"]


class ThreatHintV2IngressError(ValueError):
    """The local ThreatHint-v2 ingress boundary or frame is invalid."""


class ThreatHintV2SessionResolver(Protocol):  # pylint: disable=too-few-public-methods
    """Explicit interface for separately trusted active-session state.

    Implementations resolve one untrusted payload report nonce against
    trusted active local sessions. They must return the trusted 32-byte
    session nonce for a known active session, or ``None`` for an unknown
    one. They must never derive trust from the candidate bytes themselves.
    """

    def resolve(self, report_nonce: bytes) -> Optional[bytes]:
        """Return the trusted active-session nonce for one lookup key."""


# pylint: disable-next=too-few-public-methods
@dataclass(frozen=True)
class ThreatHintV2IngressAck:
    """Canonical digest-bound response of the ThreatHint-v2 ingress.

    The acknowledgement carries exactly the SHA-256 payload digest, the
    protocol version 2, and the status. A ``busy`` acknowledgement is
    unbound and carries an empty digest; every other status binds the exact
    payload digest. It never contains nested wires, the nonce, or approval
    material.
    """

    status: ThreatHintV2IngressStatus
    payload_digest: str

    def to_wire(self) -> bytes:
        """Serialize the exact canonical acknowledgement frame body."""
        if self.status not in {"accepted", "rejected", "busy"}:
            raise ThreatHintV2IngressError(
                "invalid ThreatHint-v2 acknowledgement status"
            )
        if self.status == "busy":
            if self.payload_digest:
                raise ThreatHintV2IngressError(
                    "busy ThreatHint-v2 acknowledgement must be unbound"
                )
        elif not _is_hex_32(self.payload_digest):
            raise ThreatHintV2IngressError(
                "ThreatHint-v2 acknowledgement digest is invalid"
            )
        payload = {
            "payload_digest": self.payload_digest,
            "protocol_version": THREAT_HINT_V2_PROTOCOL_VERSION,
            "status": self.status,
        }
        wire = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode(
            "ascii"
        )
        if len(wire) > MAX_V2_INGRESS_ACK_BYTES:
            raise ThreatHintV2IngressError("ThreatHint-v2 acknowledgement is oversized")
        return wire

    @classmethod
    def from_wire(cls, wire: bytes) -> "ThreatHintV2IngressAck":
        """Parse one exact canonical acknowledgement; anything else fails."""
        if type(wire) is not bytes or not 0 < len(wire) <= MAX_V2_INGRESS_ACK_BYTES:
            raise ThreatHintV2IngressError("invalid ThreatHint-v2 acknowledgement size")
        try:
            payload = json.loads(wire.decode("ascii"), object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ThreatHintV2IngressError(
                "invalid ThreatHint-v2 acknowledgement"
            ) from exc
        if type(payload) is not dict or set(payload) != {
            "payload_digest",
            "protocol_version",
            "status",
        }:
            raise ThreatHintV2IngressError(
                "invalid ThreatHint-v2 acknowledgement schema"
            )
        if payload["protocol_version"] != THREAT_HINT_V2_PROTOCOL_VERSION:
            raise ThreatHintV2IngressError("unsupported ThreatHint-v2 ingress version")
        ack = cls(payload["status"], payload["payload_digest"])
        if ack.to_wire() != wire:
            raise ThreatHintV2IngressError(
                "non-canonical ThreatHint-v2 acknowledgement"
            )
        return ack


class ThreatHintV2Ingress:  # pylint: disable=too-few-public-methods
    """Resolve one canonical transport payload, then promote it once.

    The boundary is constructed with the existing promotion service, an
    injected exact active-session resolver, a separately trusted network id,
    and an injected trusted clock. No trusted material is derived here.
    """

    def __init__(
        self,
        promotion: ThreatHintV2PromotionService,
        session_resolver: ThreatHintV2SessionResolver,
        trusted_network_id: str,
        now_seconds: Callable[[], int],
    ) -> None:
        if type(trusted_network_id) is not str:
            raise ThreatHintV2IngressError("trusted network id must be text")
        try:
            validate_network_id(trusted_network_id)
        except ValueError as exc:
            raise ThreatHintV2IngressError("trusted network id is invalid") from exc
        if not hasattr(promotion, "promote") or not callable(promotion.promote):
            raise ThreatHintV2IngressError("promotion service is invalid")
        if not hasattr(session_resolver, "resolve") or not callable(
            session_resolver.resolve
        ):
            raise ThreatHintV2IngressError("session resolver is invalid")
        if not callable(now_seconds):
            raise ThreatHintV2IngressError("now_seconds must be callable")
        self._promotion = promotion
        self._resolver = session_resolver
        self._network_id = trusted_network_id
        self._now_seconds = now_seconds

    # Every gate returns early and independently; fail-closed order is explicit.
    # pylint: disable=too-many-return-statements
    def process(self, wire: bytes) -> ThreatHintV2IngressAck:
        """Return a digest-bound status after every required local gate.

        Invalid transport never reaches the resolver or promotion; an
        unknown or mismatched session never reaches promotion. Only the
        SHA-256 payload digest and the status leave this boundary.
        """
        if type(wire) is not bytes or not 0 < len(wire) <= MAX_TRANSPORT_PAYLOAD_BYTES:
            return ThreatHintV2IngressAck("rejected", _ZERO_DIGEST)
        digest = hashlib.sha256(wire).hexdigest()

        # Gate 1: parse the exact transport against the trusted network.
        try:
            payload = ThreatHintV2TransportPayload.parse_canonical(
                wire, self._network_id
            )
        except ThreatHintV2TransportError:
            return ThreatHintV2IngressAck("rejected", digest)

        # Gate 2: resolve the untrusted nonce against trusted active sessions.
        try:
            resolved_nonce = self._resolver.resolve(payload.report_nonce)
        except Exception:  # pylint: disable=broad-exception-caught
            # Trusted local session state failed; no candidate fault is implied.
            return ThreatHintV2IngressAck("busy", "")
        if (
            resolved_nonce is None
            or type(resolved_nonce) is not bytes
            or len(resolved_nonce) != REPORT_NONCE_BYTES
            or resolved_nonce != payload.report_nonce
        ):
            return ThreatHintV2IngressAck("rejected", digest)

        # Gate 3: obtain the trusted current time only from the injected clock.
        try:
            current_time = self._now_seconds()
        except Exception:  # pylint: disable=broad-exception-caught
            return ThreatHintV2IngressAck("busy", "")
        if (
            type(current_time) is not int
            or current_time < 1
            or current_time > UINT64_MAX
        ):
            return ThreatHintV2IngressAck("busy", "")

        # Gate 4: promote the exact original wires with trusted context only.
        try:
            self._promotion.promote(
                payload.envelope_wire,
                payload.bundle_wire,
                payload.approval_wire,
                report_nonce=resolved_nonce,
                current_time=current_time,
            )
        except ThreatHintV2PromotionBusyError:
            return ThreatHintV2IngressAck("busy", "")
        except ThreatHintV2PromotionReplayError:
            return ThreatHintV2IngressAck("rejected", digest)
        except ThreatHintV2PromotionUnavailableError:
            return ThreatHintV2IngressAck("busy", "")
        except ThreatHintV2PromotionError:
            return ThreatHintV2IngressAck("rejected", digest)
        except Exception:  # pylint: disable=broad-exception-caught
            # Unexpected trusted-side failure; fail closed without leaking.
            return ThreatHintV2IngressAck("busy", "")
        return ThreatHintV2IngressAck("accepted", digest)


class ThreatHintV2IngressServer:  # pylint: disable=too-many-instance-attributes
    """Single-frame owner-only AF_UNIX server with bounded worker lifetime."""

    def __init__(
        self,
        path: Path,
        ingress: ThreatHintV2Ingress,
        *,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        io_timeout_seconds: float = DEFAULT_IO_TIMEOUT_SECONDS,
    ) -> None:
        if type(max_connections) is not int or max_connections < 1:
            raise ThreatHintV2IngressError("max_connections must be positive")
        if not 0 < io_timeout_seconds <= 60:
            raise ThreatHintV2IngressError("io timeout must be in (0, 60] seconds")
        if not hasattr(ingress, "process") or not callable(ingress.process):
            raise ThreatHintV2IngressError("ThreatHint-v2 ingress is invalid")
        self._path = _validate_socket_path(path)
        self._ingress = ingress
        self._max_connections = max_connections
        self._io_timeout = io_timeout_seconds
        self._listener: socket.socket | None = None
        self._accept_task: asyncio.Task[None] | None = None
        self._active = 0
        self._active_lock = asyncio.Lock()
        self._socket_identity: tuple[int, int] | None = None
        self._workers: set[asyncio.Task[None]] = set()
        self._executor: ThreadPoolExecutor | None = None

    async def start(self) -> None:
        """Bind the owner-only socket and start the bounded accept loop."""
        if self._listener is not None:
            raise ThreatHintV2IngressError("ThreatHint-v2 ingress is already running")
        if self._executor is not None:
            raise ThreatHintV2IngressError("ThreatHint-v2 ingress is still stopping")
        self._executor = ThreadPoolExecutor(
            max_workers=self._max_connections,
            thread_name_prefix="prometheus-threat-hint-v2",
        )
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self._path))
            os.chmod(self._path, 0o600)
            path_stat = self._path.lstat()
            if not stat.S_ISSOCK(path_stat.st_mode):
                raise ThreatHintV2IngressError(
                    "ThreatHint-v2 ingress path is not a socket"
                )
            self._socket_identity = (path_stat.st_dev, path_stat.st_ino)
            listener.listen(_LISTEN_BACKLOG)
            listener.setblocking(False)
        except BaseException:
            listener.close()
            _unlink_owned_socket(self._path, self._socket_identity)
            self._socket_identity = None
            executor = self._executor
            self._executor = None
            if executor is not None:
                executor.shutdown(wait=True, cancel_futures=True)
            raise
        self._listener = listener
        self._accept_task = asyncio.create_task(self._accept_loop())

    async def close(self) -> None:
        """Stop accepting, cancel bounded workers, and unlink the owned socket."""
        if self._accept_task is not None:
            self._accept_task.cancel()
            await asyncio.gather(self._accept_task, return_exceptions=True)
            self._accept_task = None
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        workers = tuple(self._workers)
        for worker in workers:
            worker.cancel()
        if workers:
            await asyncio.gather(*workers, return_exceptions=True)
        executor = self._executor
        self._executor = None
        if executor is not None:
            # Running promotion calls cannot be safely killed as Python threads.
            # Wait for the bounded trusted work to finish before close returns.
            await asyncio.to_thread(
                executor.shutdown,
                wait=True,
                cancel_futures=True,
            )
        _unlink_owned_socket(self._path, self._socket_identity)
        self._socket_identity = None

    async def __aenter__(self) -> "ThreatHintV2IngressServer":
        await self.start()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    async def _accept_loop(self) -> None:
        loop = asyncio.get_running_loop()
        listener = self._listener
        if listener is None:
            return
        while True:
            connection, _address = await loop.sock_accept(listener)
            connection.setblocking(False)
            if not _has_same_euid_peer(connection):
                connection.close()
                continue
            async with self._active_lock:
                admitted = self._active < self._max_connections
                if admitted:
                    self._active += 1
            if not admitted:
                await self._serve_busy_connection(connection)
                continue
            worker = asyncio.create_task(self._serve_connection(connection))
            self._workers.add(worker)
            worker.add_done_callback(self._workers.discard)

    async def _serve_busy_connection(self, connection: socket.socket) -> None:
        try:
            _reader, writer = await asyncio.open_unix_connection(sock=connection)
        except (OSError, ValueError):
            connection.close()
            return
        try:
            await asyncio.wait_for(
                _write_frame(writer, ThreatHintV2IngressAck("busy", "").to_wire()),
                self._io_timeout,
            )
        except (TimeoutError, ConnectionError, OSError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def _serve_connection(self, connection: socket.socket) -> None:
        try:
            reader, writer = await asyncio.open_unix_connection(sock=connection)
        except (OSError, ValueError):
            connection.close()
            async with self._active_lock:
                self._active -= 1
            return
        try:
            prefix = await asyncio.wait_for(
                reader.readexactly(_FRAME_PREFIX_BYTES), self._io_timeout
            )
            frame_size = int.from_bytes(prefix, "big")
            if not 0 < frame_size <= MAX_TRANSPORT_PAYLOAD_BYTES:
                await asyncio.wait_for(
                    _write_frame(
                        writer,
                        ThreatHintV2IngressAck("rejected", _ZERO_DIGEST).to_wire(),
                    ),
                    self._io_timeout,
                )
                return
            wire = await asyncio.wait_for(
                reader.readexactly(frame_size), self._io_timeout
            )
            executor = self._executor
            if executor is None:
                return
            ack = await asyncio.get_running_loop().run_in_executor(
                executor, self._ingress.process, wire
            )
            await asyncio.wait_for(
                _write_frame(writer, ack.to_wire()), self._io_timeout
            )
        except (asyncio.IncompleteReadError, TimeoutError, ConnectionError, OSError):
            pass
        finally:
            async with self._active_lock:
                self._active -= 1
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass


async def _write_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    writer.write(len(payload).to_bytes(_FRAME_PREFIX_BYTES, "big") + payload)
    await writer.drain()


def _has_same_euid_peer(connection: socket.socket) -> bool:
    """Require an identical peer effective uid where the platform exposes it.

    Where no peer-credential mechanism exists, the ``0600`` socket inside an
    owner-only ``0700`` parent remains the only local access gate.
    """
    if os.name != "posix" or not hasattr(os, "geteuid"):
        return True
    expected_uid = os.geteuid()
    getpeereid = getattr(connection, "getpeereid", None)
    if callable(getpeereid):
        try:
            peer_uid, _peer_gid = getpeereid()
            return peer_uid == expected_uid
        except OSError:
            return False
    so_peercred = getattr(socket, "SO_PEERCRED", None)
    if so_peercred is not None:
        try:
            credentials = connection.getsockopt(
                socket.SOL_SOCKET, so_peercred, struct.calcsize("3i")
            )
            _pid, uid, _gid = struct.unpack("3i", credentials)
            return uid == expected_uid
        except OSError:
            return False
    return True


def _validate_socket_path(path: Path) -> Path:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or path.name in {"", ".", ".."}
    ):
        raise ThreatHintV2IngressError("ThreatHint-v2 socket path must be absolute")
    resolved_parent = path.parent.resolve(strict=True)
    parent_stat = resolved_parent.stat()
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != os.getuid()
        or parent_stat.st_mode & 0o077
    ):
        raise ThreatHintV2IngressError(
            "ThreatHint-v2 socket parent must be owner-controlled"
        )
    candidate = resolved_parent / path.name
    if candidate.exists() or candidate.is_symlink():
        raise ThreatHintV2IngressError("ThreatHint-v2 socket path already exists")
    if len(os.fsencode(candidate)) >= 100:
        raise ThreatHintV2IngressError("ThreatHint-v2 socket path is too long")
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
            raise ThreatHintV2IngressError("duplicate ThreatHint-v2 field")
        result[key] = value
    return result


def _is_hex_32(value: str) -> bool:
    return type(value) is str and bool(_LOWER_HEX_32.fullmatch(value))
