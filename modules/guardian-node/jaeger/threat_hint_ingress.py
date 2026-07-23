"""Fail-closed owner-only ingress for canonical Light Client ThreatHints.

The libp2p peer is transport metadata only. This boundary re-parses the exact
schema-v1 bytes, applies freshness and persistent replay policy, invokes an
explicitly injected proof verifier, and admits verified hints to a bounded
analyzer handoff. No production proof verifier is supplied by this module.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import signal
import sqlite3
import stat
import subprocess
from contextlib import closing
from dataclasses import dataclass, fields
from pathlib import Path
from collections.abc import Callable
from typing import Final, Literal, Protocol

THREAT_HINT_PROTOCOL_VERSION: Final[int] = 1
MAX_THREAT_HINT_WIRE_BYTES: Final[int] = 2_048
MAX_THREAT_PROOF_BYTES: Final[int] = 1_024
MAX_HINT_AGE_SECONDS: Final[int] = 300
MAX_FUTURE_SKEW_SECONDS: Final[int] = 30
MAX_INGRESS_ACK_BYTES: Final[int] = 384
DEFAULT_IO_TIMEOUT_SECONDS: Final[float] = 5.0
DEFAULT_MAX_CONNECTIONS: Final[int] = 32
DEFAULT_VERIFIER_TIMEOUT_SECONDS: Final[float] = 3.0

_FRAME_PREFIX_BYTES = 4
_SQLITE_SCHEMA_VERSION = 1
_MAX_SQLITE_INT = (1 << 63) - 1
_LOWER_HEX_32 = re.compile(r"[0-9a-f]{64}")
_LOWER_HEX_PROOF = re.compile(r"(?:[0-9a-f]{2}){1,1024}")
_INDICATOR_TYPES = {"file_hash", "behavior", "network", "api_call"}
_PROOF_SYSTEMS = {"groth16_kip16_v1", "development_stub_v1"}
_NETWORK_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}[a-z0-9]")
VERIFICATION_DOMAIN: Final[str] = "prometheus-threat-hint-v1"

ThreatHintStatus = Literal["accepted", "duplicate", "rejected", "busy"]
AdmissionStatus = Literal["accepted", "duplicate", "rejected"]


class ThreatHintIngressError(ValueError):
    """The local ThreatHint boundary or frame is invalid."""


class ThreatHintReplayError(ThreatHintIngressError):
    """Persistent replay state rejected a nonce, hash, or clock transition."""


class ThreatProofVerifierUnavailable(ThreatHintIngressError):
    """No approved proof verifier is currently available."""


@dataclass(frozen=True)
class CanonicalThreatHint:
    """Exact schema-v1 ThreatHint representation used by the verifier boundary."""

    schema_version: int
    threat_hash: str
    confidence_bps: int
    indicator_type: str
    proof_system: str
    proof: str
    report_nonce: str
    observed_at: int

    @classmethod
    def from_wire(cls, wire: bytes) -> "CanonicalThreatHint":
        """Parse exact-schema canonical JSON under the transport size cap."""
        if (
            not isinstance(wire, bytes)
            or not 0 < len(wire) <= MAX_THREAT_HINT_WIRE_BYTES
        ):
            raise ThreatHintIngressError("ThreatHint wire size is invalid")
        try:
            decoded = json.loads(wire.decode("ascii"), object_pairs_hook=_unique_object)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            ThreatHintIngressError,
        ) as exc:
            raise ThreatHintIngressError("ThreatHint wire is not strict JSON") from exc
        expected_fields = {field.name for field in fields(cls)}
        if not isinstance(decoded, dict) or set(decoded) != expected_fields:
            raise ThreatHintIngressError("ThreatHint wire schema is invalid")
        try:
            envelope = cls(**decoded)
        except TypeError as exc:
            raise ThreatHintIngressError("ThreatHint wire fields are invalid") from exc
        envelope._validate()
        if envelope.to_wire() != wire:
            raise ThreatHintIngressError(
                "ThreatHint wire must use canonical JSON encoding"
            )
        return envelope

    def to_wire(self) -> bytes:
        """Serialize in the exact Rust schema field order."""
        payload = {
            "schema_version": self.schema_version,
            "threat_hash": self.threat_hash,
            "confidence_bps": self.confidence_bps,
            "indicator_type": self.indicator_type,
            "proof_system": self.proof_system,
            "proof": self.proof,
            "report_nonce": self.report_nonce,
            "observed_at": self.observed_at,
        }
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode(
            "ascii"
        )

    def _validate(self) -> None:
        if not _is_int(self.schema_version) or self.schema_version != 1:
            raise ThreatHintIngressError("unsupported ThreatHint schema version")
        if not isinstance(self.threat_hash, str) or not _is_hex_32(self.threat_hash):
            raise ThreatHintIngressError("ThreatHint hash is invalid")
        if not _is_int(self.confidence_bps) or not 1 <= self.confidence_bps <= 10_000:
            raise ThreatHintIngressError("ThreatHint confidence is invalid")
        if self.indicator_type not in _INDICATOR_TYPES:
            raise ThreatHintIngressError("ThreatHint indicator type is invalid")
        if self.proof_system not in _PROOF_SYSTEMS:
            raise ThreatHintIngressError("ThreatHint proof system is invalid")
        if not isinstance(self.proof, str) or not _LOWER_HEX_PROOF.fullmatch(
            self.proof
        ):
            raise ThreatHintIngressError("ThreatHint proof is invalid")
        if not isinstance(self.report_nonce, str) or not _is_hex_32(self.report_nonce):
            raise ThreatHintIngressError("ThreatHint report nonce is invalid")
        if not _is_timestamp(self.observed_at):
            raise ThreatHintIngressError("ThreatHint observation time is invalid")


@dataclass(frozen=True)
class ThreatProofContext:
    """Trusted local public inputs that are never supplied by the network peer."""

    network_id: str
    verification_domain: str = VERIFICATION_DOMAIN

    def __post_init__(self) -> None:
        if (
            not isinstance(self.network_id, str)
            or not 1 < len(self.network_id) <= 64
            or not _NETWORK_ID.fullmatch(self.network_id)
            or self.verification_domain != VERIFICATION_DOMAIN
        ):
            raise ThreatHintIngressError("ThreatHint proof context is invalid")


class ThreatProofVerifier(Protocol):
    """Explicit, side-effect-free interface for an approved proof verifier.

    Implementations must perform only bounded verification. Cancellation can
    discard a thread result but cannot forcibly terminate arbitrary native code.
    """

    def verify(
        self,
        envelope: CanonicalThreatHint,
        canonical_wire: bytes,
        context: ThreatProofContext,
    ) -> bool:
        """Return a real bool only after complete public proof verification."""


class UnavailableThreatProofVerifier:  # pylint: disable=too-few-public-methods
    """Production-safe default while no approved Groth16 verifier is available."""

    def verify(
        self,
        envelope: CanonicalThreatHint,
        canonical_wire: bytes,
        context: ThreatProofContext,
    ) -> bool:
        del envelope, canonical_wire, context
        raise ThreatProofVerifierUnavailable("approved Groth16 verifier unavailable")


class Kip16Groth16Verifier:  # pylint: disable=too-few-public-methods
    """Bounded adapter for the manifest-pinned Rust Groth16 verifier."""

    def __init__(
        self,
        binary_path: Path,
        manifest_path: Path,
        expected_manifest_sha256: str,
        *,
        timeout_seconds: float = DEFAULT_VERIFIER_TIMEOUT_SECONDS,
    ) -> None:
        if not isinstance(expected_manifest_sha256, str) or not _is_hex_32(
            expected_manifest_sha256
        ):
            raise ThreatHintIngressError("verifier manifest anchor is invalid")
        if not 0 < timeout_seconds <= 60:
            raise ThreatHintIngressError("verifier timeout must be in (0, 60] seconds")
        self._binary_path = _validate_verifier_binary(binary_path)
        self._manifest_path = _validate_owner_input_file(manifest_path)
        self._manifest_sha256 = expected_manifest_sha256
        self._timeout_seconds = timeout_seconds

    def verify(
        self,
        envelope: CanonicalThreatHint,
        canonical_wire: bytes,
        context: ThreatProofContext,
    ) -> bool:
        if (
            envelope.to_wire() != canonical_wire
            or envelope.proof_system != "groth16_kip16_v1"
            or context.verification_domain != VERIFICATION_DOMAIN
        ):
            return False
        process: subprocess.Popen[bytes] | None = None
        try:
            binary_path = _validate_verifier_binary(self._binary_path)
            manifest_path = _validate_owner_input_file(self._manifest_path)
            process = subprocess.Popen(  # noqa: S603 - fixed trusted binary and args
                [
                    str(binary_path),
                    "verify",
                    "--manifest",
                    str(manifest_path),
                    "--expected-manifest-sha256",
                    self._manifest_sha256,
                    "--network-id",
                    context.network_id,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                cwd="/",
                env={"LANG": "C", "LC_ALL": "C"},
                start_new_session=True,
            )
            process.communicate(canonical_wire, timeout=self._timeout_seconds)
        except (OSError, subprocess.SubprocessError, ThreatHintIngressError) as exc:
            if process is not None and process.poll() is None:
                _kill_process_group(process)
            raise ThreatProofVerifierUnavailable(
                "approved Groth16 verifier unavailable"
            ) from exc
        if process.returncode == 0:
            return True
        if process.returncode == 1:
            return False
        raise ThreatProofVerifierUnavailable("approved Groth16 verifier unavailable")


@dataclass(frozen=True)
class VerifiedThreatHintJob:
    """Durable post-verification work without invented analyzer indicators."""

    payload_digest: str
    canonical_wire: bytes
    network_id: str
    admitted_at: int


@dataclass(frozen=True)
class ThreatHintIngressAck:
    """Canonical digest-bound response to the Rust transport sidecar."""

    status: ThreatHintStatus
    payload_digest: str

    def to_wire(self) -> bytes:
        if self.status not in {"accepted", "duplicate", "rejected", "busy"}:
            raise ThreatHintIngressError("invalid ThreatHint acknowledgement status")
        if self.status == "busy":
            if self.payload_digest:
                raise ThreatHintIngressError("busy acknowledgement must be unbound")
        elif not _is_hex_32(self.payload_digest):
            raise ThreatHintIngressError("acknowledgement digest is invalid")
        payload = {
            "payload_digest": self.payload_digest,
            "protocol_version": THREAT_HINT_PROTOCOL_VERSION,
            "status": self.status,
        }
        wire = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode(
            "ascii"
        )
        if len(wire) > MAX_INGRESS_ACK_BYTES:
            raise ThreatHintIngressError("ThreatHint acknowledgement is oversized")
        return wire

    @classmethod
    def from_wire(cls, wire: bytes) -> "ThreatHintIngressAck":
        if not isinstance(wire, bytes) or not 0 < len(wire) <= MAX_INGRESS_ACK_BYTES:
            raise ThreatHintIngressError("invalid ThreatHint acknowledgement size")
        try:
            payload = json.loads(wire.decode("ascii"), object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ThreatHintIngressError("invalid ThreatHint acknowledgement") from exc
        if not isinstance(payload, dict) or set(payload) != {
            "payload_digest",
            "protocol_version",
            "status",
        }:
            raise ThreatHintIngressError("invalid ThreatHint acknowledgement schema")
        if payload["protocol_version"] != THREAT_HINT_PROTOCOL_VERSION:
            raise ThreatHintIngressError("unsupported ThreatHint ingress version")
        status = payload["status"]
        digest = payload["payload_digest"]
        if status not in {"accepted", "duplicate", "rejected", "busy"}:
            raise ThreatHintIngressError("invalid ThreatHint acknowledgement status")
        if not isinstance(digest, str):
            raise ThreatHintIngressError("invalid ThreatHint acknowledgement digest")
        ack = cls(status, digest)
        if ack.to_wire() != wire:
            raise ThreatHintIngressError("non-canonical ThreatHint acknowledgement")
        return ack


class ThreatHintReplayLedger:
    """Owner-only replay state and analyzer outbox committed in one transaction."""

    def __init__(self, path: Path) -> None:
        self.path = _prepare_ledger_path(path)
        with closing(self._connect()) as connection, connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, _SQLITE_SCHEMA_VERSION):
                raise ThreatHintIngressError("unsupported ThreatHint ledger schema")
            connection.execute("""
                CREATE TABLE IF NOT EXISTS hint_admissions (
                    report_nonce TEXT PRIMARY KEY,
                    threat_hash TEXT NOT NULL UNIQUE,
                    payload_digest TEXT NOT NULL UNIQUE,
                    observed_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    admitted_at INTEGER NOT NULL,
                    wire BLOB NOT NULL
                ) STRICT
                """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS analyzer_outbox (
                    payload_digest TEXT PRIMARY KEY,
                    canonical_wire BLOB NOT NULL,
                    network_id TEXT NOT NULL,
                    admitted_at INTEGER NOT NULL,
                    delivered_at INTEGER,
                    FOREIGN KEY (payload_digest)
                        REFERENCES hint_admissions(payload_digest)
                ) STRICT
                """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS ledger_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    high_water_seconds INTEGER NOT NULL
                ) STRICT
                """)
            connection.execute(
                "INSERT OR IGNORE INTO ledger_state "
                "(singleton, high_water_seconds) VALUES (1, 0)"
            )
            connection.execute(f"PRAGMA user_version = {_SQLITE_SCHEMA_VERSION}")

    def admit(
        self,
        envelope: CanonicalThreatHint,
        wire: bytes,
        context: ThreatProofContext,
        now_seconds: int,
    ) -> AdmissionStatus:
        """Atomically commit replay identities and one durable outbox job."""
        if (
            not _is_timestamp(now_seconds)
            or envelope.to_wire() != wire
            or not _is_fresh(envelope, now_seconds)
        ):
            raise ThreatHintIngressError("ThreatHint replay input is invalid")
        payload_digest = hashlib.sha256(wire).hexdigest()
        expires_at = envelope.observed_at + MAX_HINT_AGE_SECONDS
        try:
            with closing(self._connect()) as connection, connection:
                connection.execute("BEGIN IMMEDIATE")
                self._advance_time(connection, now_seconds)
                connection.execute(
                    """
                    DELETE FROM analyzer_outbox
                    WHERE delivered_at IS NOT NULL
                      AND payload_digest IN (
                          SELECT payload_digest FROM hint_admissions
                          WHERE expires_at < ?
                      )
                    """,
                    (now_seconds,),
                )
                connection.execute(
                    """
                    DELETE FROM hint_admissions
                    WHERE expires_at < ?
                      AND NOT EXISTS (
                          SELECT 1 FROM analyzer_outbox
                          WHERE analyzer_outbox.payload_digest =
                                hint_admissions.payload_digest
                      )
                    """,
                    (now_seconds,),
                )
                connection.execute(
                    """
                    INSERT INTO hint_admissions (
                        report_nonce, threat_hash, payload_digest, observed_at,
                        expires_at, admitted_at, wire
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        envelope.report_nonce,
                        envelope.threat_hash,
                        payload_digest,
                        envelope.observed_at,
                        expires_at,
                        now_seconds,
                        wire,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO analyzer_outbox (
                        payload_digest, canonical_wire, network_id, admitted_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (payload_digest, wire, context.network_id, now_seconds),
                )
            return "accepted"
        except sqlite3.IntegrityError:
            with closing(self._connect()) as connection, connection:
                row = connection.execute(
                    """
                    SELECT payload_digest, wire FROM hint_admissions
                    WHERE report_nonce = ? OR threat_hash = ? OR payload_digest = ?
                    """,
                    (envelope.report_nonce, envelope.threat_hash, payload_digest),
                ).fetchone()
            if row is not None and row[0] == payload_digest and bytes(row[1]) == wire:
                return "duplicate"
            return "rejected"

    def pending_jobs(self, limit: int) -> list[VerifiedThreatHintJob]:
        """Read one bounded recovery batch without inventing analyzer data."""
        if not 1 <= limit <= 256:
            raise ThreatHintIngressError("ThreatHint outbox limit is invalid")
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                """
                SELECT payload_digest, canonical_wire, network_id, admitted_at
                FROM analyzer_outbox
                WHERE delivered_at IS NULL
                ORDER BY admitted_at, payload_digest
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            VerifiedThreatHintJob(str(row[0]), bytes(row[1]), str(row[2]), int(row[3]))
            for row in rows
        ]

    def mark_delivered(self, payload_digest: str, delivered_at: int) -> None:
        """Idempotently mark a durable job after a future explicit adapter succeeds."""
        if not _is_hex_32(payload_digest):
            raise ThreatHintIngressError("outbox digest is invalid")
        if not _is_timestamp(delivered_at):
            raise ThreatHintIngressError("outbox delivery time is invalid")
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE analyzer_outbox
                SET delivered_at = COALESCE(delivered_at, ?)
                WHERE payload_digest = ?
                """,
                (delivered_at, payload_digest),
            )
            if cursor.rowcount != 1:
                raise ThreatHintReplayError("ThreatHint outbox job is unknown")

    @staticmethod
    def _advance_time(connection: sqlite3.Connection, now_seconds: int) -> None:
        row = connection.execute(
            "SELECT high_water_seconds FROM ledger_state WHERE singleton = 1"
        ).fetchone()
        if row is None or not isinstance(row[0], int):
            raise ThreatHintIngressError("ThreatHint ledger state is invalid")
        if now_seconds < row[0]:
            raise ThreatHintReplayError("ThreatHint ledger clock rollback detected")
        connection.execute(
            "UPDATE ledger_state SET high_water_seconds = ? WHERE singleton = 1",
            (now_seconds,),
        )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=0.25, isolation_level=None)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA trusted_schema = OFF")
        return connection


class ThreatHintIngress:
    """Verify and durably admit one canonical hint to the local outbox."""

    def __init__(
        self,
        ledger: ThreatHintReplayLedger,
        verifier: ThreatProofVerifier,
        context: ThreatProofContext,
    ) -> None:
        self._ledger = ledger
        self._verifier = verifier
        self._context = context

    async def process(self, wire: bytes, now_seconds: int) -> ThreatHintIngressAck:
        """Return a digest-bound status after every required local gate."""
        digest = hashlib.sha256(wire).hexdigest()
        try:
            envelope = CanonicalThreatHint.from_wire(wire)
            if not _is_fresh(envelope, now_seconds):
                return ThreatHintIngressAck("rejected", digest)
            if envelope.proof_system != "groth16_kip16_v1":
                return ThreatHintIngressAck("rejected", digest)
            verified = await asyncio.to_thread(
                self._verifier.verify, envelope, wire, self._context
            )
            if not isinstance(verified, bool) or not verified:
                return ThreatHintIngressAck("rejected", digest)
            admission = await asyncio.to_thread(
                self._ledger.admit,
                envelope,
                wire,
                self._context,
                now_seconds,
            )
        except ThreatProofVerifierUnavailable:
            return ThreatHintIngressAck("busy", "")
        except ThreatHintReplayError:
            return ThreatHintIngressAck("rejected", digest)
        except sqlite3.OperationalError:
            return ThreatHintIngressAck("busy", "")
        except (ThreatHintIngressError, sqlite3.Error, OSError):
            return ThreatHintIngressAck("rejected", digest)

        if admission == "duplicate":
            return ThreatHintIngressAck("duplicate", digest)
        if admission != "accepted":
            return ThreatHintIngressAck("rejected", digest)
        return ThreatHintIngressAck("accepted", digest)


class ThreatHintIngressServer:  # pylint: disable=too-many-instance-attributes
    """Single-frame owner-only AF_UNIX server with bounded worker lifetime."""

    def __init__(
        self,
        path: Path,
        ingress: ThreatHintIngress,
        *,
        now_seconds: Callable[[], int],
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        io_timeout_seconds: float = DEFAULT_IO_TIMEOUT_SECONDS,
    ) -> None:
        if max_connections < 1:
            raise ThreatHintIngressError("max_connections must be positive")
        if not 0 < io_timeout_seconds <= 60:
            raise ThreatHintIngressError("io timeout must be in (0, 60] seconds")
        if not callable(now_seconds):
            raise ThreatHintIngressError("now_seconds must be callable")
        self._path = _validate_socket_path(path)
        self._ingress = ingress
        self._now_seconds = now_seconds
        self._max_connections = max_connections
        self._io_timeout = io_timeout_seconds
        self._server: asyncio.AbstractServer | None = None
        self._active = 0
        self._active_lock = asyncio.Lock()
        self._socket_identity: tuple[int, int] | None = None
        self._workers: set[asyncio.Task[ThreatHintIngressAck]] = set()

    async def start(self) -> None:
        if self._server is not None:
            raise ThreatHintIngressError("ThreatHint ingress is already running")
        try:
            self._server = await asyncio.start_unix_server(
                self._handle_connection, path=str(self._path)
            )
            path_stat = self._path.lstat()
            if not stat.S_ISSOCK(path_stat.st_mode):
                raise ThreatHintIngressError("ThreatHint ingress path is not a socket")
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
        workers = tuple(self._workers)
        for worker in workers:
            worker.cancel()
        if workers:
            await asyncio.gather(*workers, return_exceptions=True)
        _unlink_owned_socket(self._path, self._socket_identity)
        self._socket_identity = None

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        admitted = False
        worker: asyncio.Task[ThreatHintIngressAck] | None = None
        try:
            async with self._active_lock:
                if self._active < self._max_connections:
                    self._active += 1
                    admitted = True
            if not admitted:
                await asyncio.wait_for(
                    _write_frame(writer, ThreatHintIngressAck("busy", "").to_wire()),
                    self._io_timeout,
                )
                return

            prefix = await asyncio.wait_for(
                reader.readexactly(_FRAME_PREFIX_BYTES), self._io_timeout
            )
            frame_size = int.from_bytes(prefix, "big")
            if not 0 < frame_size <= MAX_THREAT_HINT_WIRE_BYTES:
                await _write_frame(
                    writer, ThreatHintIngressAck("rejected", "0" * 64).to_wire()
                )
                return
            wire = await asyncio.wait_for(
                reader.readexactly(frame_size), self._io_timeout
            )
            worker = asyncio.create_task(self._process_with_permit(wire))
            self._workers.add(worker)
            worker.add_done_callback(self._workers.discard)
            admitted = False
            ack = await asyncio.wait_for(asyncio.shield(worker), self._io_timeout)
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

    async def _process_with_permit(self, wire: bytes) -> ThreatHintIngressAck:
        try:
            return await self._ingress.process(wire, self._now_seconds())
        finally:
            async with self._active_lock:
                self._active -= 1


async def submit_to_threat_hint_ingress(
    path: Path,
    wire: bytes,
    *,
    timeout_seconds: float = DEFAULT_IO_TIMEOUT_SECONDS,
) -> ThreatHintIngressAck:
    """Submit one exact canonical hint to a local verification ingress."""
    if not 0 < len(wire) <= MAX_THREAT_HINT_WIRE_BYTES:
        raise ThreatHintIngressError("invalid outbound ThreatHint size")
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
            raise ThreatHintIngressError("invalid ThreatHint acknowledgement size")
        ack_wire = await asyncio.wait_for(reader.readexactly(ack_size), timeout_seconds)
        ack = ThreatHintIngressAck.from_wire(ack_wire)
        if (
            ack.status != "busy"
            and ack.payload_digest != hashlib.sha256(wire).hexdigest()
        ):
            raise ThreatHintIngressError("acknowledgement does not match ThreatHint")
        return ack
    finally:
        writer.close()
        await writer.wait_closed()


async def _write_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    writer.write(len(payload).to_bytes(_FRAME_PREFIX_BYTES, "big") + payload)
    await writer.drain()


def _is_fresh(envelope: CanonicalThreatHint, now_seconds: int) -> bool:
    return (
        _is_timestamp(now_seconds)
        and envelope.observed_at <= now_seconds + MAX_FUTURE_SKEW_SECONDS
        and now_seconds <= envelope.observed_at + MAX_HINT_AGE_SECONDS
    )


def _prepare_ledger_path(path: Path) -> Path:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise ThreatHintIngressError("ThreatHint ledger path must be absolute")
    parent = path.parent.resolve(strict=True)
    parent_stat = parent.stat()
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != os.getuid()
        or parent_stat.st_mode & 0o077
    ):
        raise ThreatHintIngressError("ThreatHint ledger parent must be owner-only")
    candidate = parent / path.name
    if candidate.is_symlink():
        raise ThreatHintIngressError("ThreatHint ledger must not be a symlink")
    if candidate.exists():
        current = candidate.stat()
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_uid != os.getuid()
            or current.st_mode & 0o177
            or current.st_mode & 0o600 != 0o600
        ):
            raise ThreatHintIngressError("ThreatHint ledger must be owner-only")
    else:
        descriptor = os.open(
            candidate,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
        os.close(descriptor)
    return candidate


def _validate_verifier_binary(path: Path) -> Path:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise ThreatHintIngressError("verifier binary path must be absolute")
    try:
        resolved = path.resolve(strict=True)
        current = path.lstat()
    except OSError as exc:
        raise ThreatHintIngressError("verifier binary is unavailable") from exc
    if (
        resolved != path
        or not stat.S_ISREG(current.st_mode)
        or current.st_uid not in {0, os.getuid()}
        or current.st_mode & 0o022
        or current.st_mode & 0o7000
        or current.st_mode & 0o100 == 0
    ):
        raise ThreatHintIngressError("verifier binary is not trusted")
    for parent in path.parents:
        parent_stat = parent.stat()
        if (
            not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_mode & 0o022
            or parent_stat.st_uid not in {0, os.getuid()}
        ):
            raise ThreatHintIngressError("verifier binary parent is not trusted")
    return resolved


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=1)
    except (OSError, subprocess.SubprocessError):
        pass


def _validate_owner_input_file(path: Path) -> Path:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise ThreatHintIngressError("verifier input path must be absolute")
    try:
        parent = path.parent.resolve(strict=True)
        parent_stat = parent.stat()
        current = path.lstat()
    except OSError as exc:
        raise ThreatHintIngressError("verifier input is unavailable") from exc
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
        or current.st_mode & 0o400 == 0
    ):
        raise ThreatHintIngressError("verifier input must be owner-only")
    return candidate


def _validate_socket_path(path: Path) -> Path:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise ThreatHintIngressError("ThreatHint socket path must be absolute")
    resolved_parent = path.parent.resolve(strict=True)
    parent_stat = resolved_parent.stat()
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != os.getuid()
        or parent_stat.st_mode & 0o077
    ):
        raise ThreatHintIngressError(
            "ThreatHint socket parent must be owner-controlled"
        )
    candidate = resolved_parent / path.name
    if candidate.exists() or candidate.is_symlink():
        raise ThreatHintIngressError("ThreatHint socket path already exists")
    if len(os.fsencode(candidate)) >= 100:
        raise ThreatHintIngressError("ThreatHint socket path is too long")
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
        and (
            current.st_dev,
            current.st_ino,
        )
        == expected_identity
    ):
        path.unlink()


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ThreatHintIngressError("duplicate ThreatHint field")
        result[key] = value
    return result


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_timestamp(value: object) -> bool:
    return _is_int(value) and 0 < value <= _MAX_SQLITE_INT


def _is_hex_32(value: str) -> bool:
    return bool(_LOWER_HEX_32.fullmatch(value))
