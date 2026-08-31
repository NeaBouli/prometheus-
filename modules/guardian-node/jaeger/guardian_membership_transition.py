"""Owner-local signed Guardian membership transition continuity.

The owner pins one public BIP340 authority key and one canonical bootstrap
membership source in an owner-only policy. Signed transitions can advance the
accepted source in an owner-only SQLite ledger, while rollback, equivocation,
replay, and trusted-clock rollback fail closed. The ledger stores canonical
source bytes so consumers never need a mutable source path.

This module verifies public signatures only. It exposes no signing or private
key path and proves no external authority, key ownership or rotation, Sybil
resistance, transport, chain attestation, deployment, or production trust.
"""

# Exact built-in types are protocol requirements.
# pylint: disable=unidiomatic-typecheck,too-many-lines
# pylint: disable=too-many-instance-attributes,too-many-boolean-expressions

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import tomllib
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path, PosixPath, WindowsPath
from typing import Final, Iterator, NoReturn

from coincurve import PublicKeyXOnly

from .guardian_membership_source import (
    MAX_MEMBERSHIP_EPOCH,
    MAX_MEMBERSHIP_SOURCE_BYTES,
    GuardianMembershipSource,
    GuardianMembershipSourceError,
    load_guardian_membership_source,
    parse_guardian_membership_source,
)
from .threat_observable import validate_network_id

MEMBERSHIP_AUTHORITY_POLICY_SCHEMA_VERSION: Final[int] = 1
MEMBERSHIP_TRANSITION_SCHEMA_VERSION: Final[int] = 1
MEMBERSHIP_TRANSITION_PROTOCOL_ID: Final[str] = (
    "/prometheus/guardian-membership-transition/1.0.0"
)
MAX_MEMBERSHIP_AUTHORITY_POLICY_BYTES: Final[int] = 4_096
MAX_MEMBERSHIP_TRANSITION_BYTES: Final[int] = 2_048
MAX_MEMBERSHIP_TRANSITION_WINDOW_MS: Final[int] = 86_400_000
MAX_MEMBERSHIP_TRANSITION_TIME_MS: Final[int] = 2**63 - 1
MEMBERSHIP_TRANSITION_DIGEST_DOMAIN: Final[bytes] = (
    b"PROMETHEUS_GUARDIAN_MEMBERSHIP_TRANSITION_V1\x00"
)
_TRANSITION_ID_DOMAIN: Final[bytes] = (
    b"PROMETHEUS_GUARDIAN_MEMBERSHIP_TRANSITION_ID_V1\x00"
)
_SQLITE_SCHEMA_VERSION: Final[int] = 1
_FIXED_HEX_32 = re.compile(r"[0-9a-f]{64}")
_FIXED_HEX_64 = re.compile(r"[0-9a-f]{128}")
_POLICY_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "network_id",
        "authority_xonly_public_key",
        "bootstrap_epoch",
        "bootstrap_membership_source_sha256",
        "bootstrap_membership_source_path",
        "ledger_path",
    }
)
_TRANSITION_FIELDS: Final[tuple[str, ...]] = (
    "schema_version",
    "protocol_id",
    "network_id",
    "previous_epoch",
    "previous_membership_source_sha256",
    "next_epoch",
    "next_membership_source_sha256",
    "not_before_ms",
    "not_after_ms",
    "nonce",
    "payload_digest",
    "signature",
)
_UNSIGNED_TRANSITION_FIELDS: Final[tuple[str, ...]] = _TRANSITION_FIELDS[:-2]


class GuardianMembershipTransitionError(ValueError):
    """Stable redacted rejection for policy, wire, source, or ledger state."""

    _MESSAGE = "guardian membership transition rejected"

    def __init__(self) -> None:
        super().__init__(self._MESSAGE)


class GuardianMembershipTransitionReplayError(GuardianMembershipTransitionError):
    """A transition identity, nonce, or target epoch was already consumed."""


class GuardianMembershipTransitionBusyError(GuardianMembershipTransitionError):
    """The durable membership boundary is currently locked."""


@dataclass(frozen=True)
class _AuthorityPolicy:
    network_id: str
    authority_xonly_public_key: bytes
    bootstrap_epoch: int
    bootstrap_membership_source_sha256: bytes
    bootstrap_membership_source_path: Path
    ledger_path: Path


@dataclass(frozen=True, init=False, repr=False)
class GuardianMembershipTransitionReceipt:
    """Data-only receipt for one locally accepted transition."""

    transition_id: bytes
    next_epoch: int
    next_membership_source_sha256: bytes
    applied_at_ms: int

    def __init__(self) -> None:
        raise TypeError("direct membership transition receipt construction is disabled")

    def __reduce__(self) -> object:
        raise TypeError("membership transition receipt is not serializable")


@dataclass(frozen=True)
class _ParsedTransition:
    wire: bytes
    transition_id: bytes
    network_id: str
    previous_epoch: int
    previous_source_digest: bytes
    next_epoch: int
    next_source_digest: bytes
    not_before_ms: int
    not_after_ms: int
    nonce: bytes
    payload_digest: bytes
    signature: bytes


class GuardianMembershipAuthority:
    """Owner-local continuity state for one pinned membership authority key."""

    def __init__(self, policy_path: Path) -> None:
        self._policy = _load_authority_policy(policy_path)
        try:
            self._verification_key = PublicKeyXOnly(
                self._policy.authority_xonly_public_key
            )
            bootstrap = load_guardian_membership_source(
                self._policy.bootstrap_membership_source_path,
                expected_network_id=self._policy.network_id,
            )
        except (ValueError, GuardianMembershipSourceError):
            raise GuardianMembershipTransitionError() from None
        if (
            bootstrap.epoch != self._policy.bootstrap_epoch
            or hashlib.sha256(bootstrap.canonical_bytes).digest()
            != self._policy.bootstrap_membership_source_sha256
        ):
            raise GuardianMembershipTransitionError()
        self._ledger_path = _prepare_ledger_path(self._policy.ledger_path)
        self._initialize_ledger(bootstrap)

    def apply_transition(
        self,
        wire: bytes,
        next_source_path: Path,
        now_ms: int,
    ) -> GuardianMembershipTransitionReceipt:
        """Verify and atomically apply one signed transition."""
        transition = _parse_transition(wire)
        if transition.network_id != self._policy.network_id:
            raise GuardianMembershipTransitionError()
        try:
            signature_valid = self._verification_key.verify(
                transition.signature, transition.payload_digest
            )
            next_source = load_guardian_membership_source(
                next_source_path, expected_network_id=self._policy.network_id
            )
        except (ValueError, GuardianMembershipSourceError):
            raise GuardianMembershipTransitionError() from None
        if (
            not signature_valid
            or next_source.epoch != transition.next_epoch
            or hashlib.sha256(next_source.canonical_bytes).digest()
            != transition.next_source_digest
            or not _is_time(now_ms)
            or not transition.not_before_ms <= now_ms < transition.not_after_ms
        ):
            raise GuardianMembershipTransitionError()

        try:
            with closing(self._connect()) as connection:
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    self._validate_ledger(connection)
                    current = connection.execute(
                        "SELECT epoch, membership_source_sha256 "
                        "FROM current_membership WHERE singleton = 1"
                    ).fetchone()
                    clock = connection.execute(
                        "SELECT high_water_ms FROM membership_clock "
                        "WHERE singleton = 1"
                    ).fetchone()
                    replay = connection.execute(
                        "SELECT 1 FROM membership_transitions "
                        "WHERE transition_id = ? OR nonce = ? OR next_epoch = ?",
                        (
                            transition.transition_id,
                            transition.nonce,
                            transition.next_epoch,
                        ),
                    ).fetchone()
                    if replay is not None:
                        raise GuardianMembershipTransitionReplayError()
                    if (
                        current is None
                        or clock is None
                        or type(current[0]) is not int
                        or type(current[1]) is not bytes
                        or type(clock[0]) is not int
                        or current[0] != transition.previous_epoch
                        or bytes(current[1]) != transition.previous_source_digest
                        or now_ms < clock[0]
                    ):
                        raise GuardianMembershipTransitionError()
                    connection.execute(
                        """
                        INSERT INTO membership_transitions (
                            transition_id, nonce, previous_epoch,
                            previous_membership_source_sha256, next_epoch,
                            next_membership_source_sha256, not_before_ms,
                            not_after_ms, applied_at_ms, transition_wire
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            transition.transition_id,
                            transition.nonce,
                            transition.previous_epoch,
                            transition.previous_source_digest,
                            transition.next_epoch,
                            transition.next_source_digest,
                            transition.not_before_ms,
                            transition.not_after_ms,
                            now_ms,
                            transition.wire,
                        ),
                    )
                    connection.execute(
                        """
                        UPDATE current_membership
                        SET epoch = ?, membership_source_sha256 = ?, source_wire = ?
                        WHERE singleton = 1
                        """,
                        (
                            transition.next_epoch,
                            transition.next_source_digest,
                            next_source.canonical_bytes,
                        ),
                    )
                    connection.execute(
                        "UPDATE membership_clock SET high_water_ms = ? "
                        "WHERE singleton = 1",
                        (now_ms,),
                    )
                    connection.commit()
                except BaseException:
                    connection.rollback()
                    raise
        except GuardianMembershipTransitionError:
            raise
        except sqlite3.IntegrityError:
            raise GuardianMembershipTransitionReplayError() from None
        except sqlite3.OperationalError as error:
            _raise_operational_error(error)
        except (sqlite3.Error, OSError, OverflowError):
            raise GuardianMembershipTransitionError() from None

        receipt = object.__new__(GuardianMembershipTransitionReceipt)
        object.__setattr__(receipt, "transition_id", transition.transition_id)
        object.__setattr__(receipt, "next_epoch", transition.next_epoch)
        object.__setattr__(
            receipt,
            "next_membership_source_sha256",
            transition.next_source_digest,
        )
        object.__setattr__(receipt, "applied_at_ms", now_ms)
        return receipt

    @contextmanager
    def current_source(
        self,
        *,
        expected_network_id: str,
        expected_epoch: int,
    ) -> Iterator[GuardianMembershipSource]:
        """Yield the exact current source while serializing transitions."""
        if (
            type(expected_network_id) is not str
            or expected_network_id != self._policy.network_id
            or not _is_epoch(expected_epoch)
        ):
            raise GuardianMembershipTransitionError()
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            self._validate_ledger(connection)
            row = connection.execute(
                "SELECT epoch, membership_source_sha256, source_wire "
                "FROM current_membership WHERE singleton = 1"
            ).fetchone()
            if (
                row is None
                or type(row[0]) is not int
                or type(row[1]) is not bytes
                or type(row[2]) is not bytes
                or row[0] != expected_epoch
                or not 0 < len(row[2]) <= MAX_MEMBERSHIP_SOURCE_BYTES
            ):
                raise GuardianMembershipTransitionError()
            source = parse_guardian_membership_source(
                bytes(row[2]), expected_network_id=expected_network_id
            )
            if source.epoch != row[0] or hashlib.sha256(
                source.canonical_bytes
            ).digest() != bytes(row[1]):
                raise GuardianMembershipTransitionError()
            yield source
        except GuardianMembershipTransitionError:
            raise
        except GuardianMembershipSourceError:
            raise GuardianMembershipTransitionError() from None
        except sqlite3.OperationalError as error:
            _raise_operational_error(error)
        except (sqlite3.Error, OSError, OverflowError):
            raise GuardianMembershipTransitionError() from None
        finally:
            if connection is not None:
                try:
                    connection.rollback()
                except sqlite3.Error:
                    pass
                connection.close()

    def _initialize_ledger(self, bootstrap: GuardianMembershipSource) -> None:
        try:
            with closing(self._connect()) as connection:
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    version = connection.execute("PRAGMA user_version").fetchone()[0]
                    if version == 0:
                        self._create_schema(connection, bootstrap)
                    elif version != _SQLITE_SCHEMA_VERSION:
                        raise GuardianMembershipTransitionError()
                    self._validate_ledger(connection)
                    connection.commit()
                except BaseException:
                    connection.rollback()
                    raise
        except GuardianMembershipTransitionError:
            raise
        except sqlite3.OperationalError as error:
            _raise_operational_error(error)
        except (sqlite3.Error, OSError, OverflowError):
            raise GuardianMembershipTransitionError() from None

    def _create_schema(
        self,
        connection: sqlite3.Connection,
        bootstrap: GuardianMembershipSource,
    ) -> None:
        existing = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
        if existing:
            raise GuardianMembershipTransitionError()
        connection.execute("""
            CREATE TABLE membership_authority (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                network_id TEXT NOT NULL,
                authority_xonly_public_key BLOB NOT NULL
                    CHECK(length(authority_xonly_public_key) = 32),
                bootstrap_epoch INTEGER NOT NULL CHECK(bootstrap_epoch >= 0),
                bootstrap_membership_source_sha256 BLOB NOT NULL
                    CHECK(length(bootstrap_membership_source_sha256) = 32)
            ) STRICT
            """)
        connection.execute("""
            CREATE TABLE current_membership (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                epoch INTEGER NOT NULL CHECK(epoch >= 0),
                membership_source_sha256 BLOB NOT NULL
                    CHECK(length(membership_source_sha256) = 32),
                source_wire BLOB NOT NULL
                    CHECK(length(source_wire) >= 1 AND length(source_wire) <= 300000)
            ) STRICT
            """)
        connection.execute("""
            CREATE TABLE membership_clock (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                high_water_ms INTEGER NOT NULL CHECK(high_water_ms >= 0)
            ) STRICT
            """)
        connection.execute("""
            CREATE TABLE membership_transitions (
                transition_id BLOB PRIMARY KEY CHECK(length(transition_id) = 32),
                nonce BLOB NOT NULL UNIQUE CHECK(length(nonce) = 32),
                previous_epoch INTEGER NOT NULL CHECK(previous_epoch >= 0),
                previous_membership_source_sha256 BLOB NOT NULL
                    CHECK(length(previous_membership_source_sha256) = 32),
                next_epoch INTEGER NOT NULL UNIQUE CHECK(next_epoch >= 0),
                next_membership_source_sha256 BLOB NOT NULL
                    CHECK(length(next_membership_source_sha256) = 32),
                not_before_ms INTEGER NOT NULL CHECK(not_before_ms >= 1),
                not_after_ms INTEGER NOT NULL CHECK(not_after_ms > not_before_ms),
                applied_at_ms INTEGER NOT NULL CHECK(applied_at_ms >= not_before_ms),
                transition_wire BLOB NOT NULL
                    CHECK(length(transition_wire) >= 1 AND length(transition_wire) <= 2048)
            ) STRICT
            """)
        connection.execute(
            "INSERT INTO membership_authority VALUES (1, ?, ?, ?, ?)",
            (
                self._policy.network_id,
                self._policy.authority_xonly_public_key,
                self._policy.bootstrap_epoch,
                self._policy.bootstrap_membership_source_sha256,
            ),
        )
        connection.execute(
            "INSERT INTO current_membership VALUES (1, ?, ?, ?)",
            (
                bootstrap.epoch,
                self._policy.bootstrap_membership_source_sha256,
                bootstrap.canonical_bytes,
            ),
        )
        connection.execute("INSERT INTO membership_clock VALUES (1, 0)")
        connection.execute(f"PRAGMA user_version = {_SQLITE_SCHEMA_VERSION}")

    def _validate_ledger(self, connection: sqlite3.Connection) -> None:
        expected_shapes = {
            "membership_authority": (
                ("singleton", "INTEGER", 0, 1),
                ("network_id", "TEXT", 1, 0),
                ("authority_xonly_public_key", "BLOB", 1, 0),
                ("bootstrap_epoch", "INTEGER", 1, 0),
                ("bootstrap_membership_source_sha256", "BLOB", 1, 0),
            ),
            "current_membership": (
                ("singleton", "INTEGER", 0, 1),
                ("epoch", "INTEGER", 1, 0),
                ("membership_source_sha256", "BLOB", 1, 0),
                ("source_wire", "BLOB", 1, 0),
            ),
            "membership_clock": (
                ("singleton", "INTEGER", 0, 1),
                ("high_water_ms", "INTEGER", 1, 0),
            ),
            "membership_transitions": (
                ("transition_id", "BLOB", 1, 1),
                ("nonce", "BLOB", 1, 0),
                ("previous_epoch", "INTEGER", 1, 0),
                ("previous_membership_source_sha256", "BLOB", 1, 0),
                ("next_epoch", "INTEGER", 1, 0),
                ("next_membership_source_sha256", "BLOB", 1, 0),
                ("not_before_ms", "INTEGER", 1, 0),
                ("not_after_ms", "INTEGER", 1, 0),
                ("applied_at_ms", "INTEGER", 1, 0),
                ("transition_wire", "BLOB", 1, 0),
            ),
        }
        table_names = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        if (
            connection.execute("PRAGMA user_version").fetchone()[0]
            != _SQLITE_SCHEMA_VERSION
            or table_names != set(expected_shapes)
            or any(
                _table_shape(connection, table) != shape
                or not _is_strict_table(connection, table, len(shape))
                for table, shape in expected_shapes.items()
            )
            or _unique_index_columns(connection, "membership_transitions")
            != {("transition_id",), ("nonce",), ("next_epoch",)}
            or any(
                _unique_index_columns(connection, table)
                for table in (
                    "membership_authority",
                    "current_membership",
                    "membership_clock",
                )
            )
        ):
            raise GuardianMembershipTransitionError()
        authority = connection.execute(
            "SELECT network_id, authority_xonly_public_key, bootstrap_epoch, "
            "bootstrap_membership_source_sha256 FROM membership_authority "
            "WHERE singleton = 1"
        ).fetchall()
        current_count = connection.execute(
            "SELECT COUNT(*) FROM current_membership"
        ).fetchone()[0]
        clock_count = connection.execute(
            "SELECT COUNT(*) FROM membership_clock"
        ).fetchone()[0]
        if (
            authority
            != [
                (
                    self._policy.network_id,
                    self._policy.authority_xonly_public_key,
                    self._policy.bootstrap_epoch,
                    self._policy.bootstrap_membership_source_sha256,
                )
            ]
            or current_count != 1
            or clock_count != 1
        ):
            raise GuardianMembershipTransitionError()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._ledger_path, timeout=0.25, isolation_level=None
        )
        mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()[0]
        if str(mode).lower() != "delete":
            connection.close()
            raise GuardianMembershipTransitionError()
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA trusted_schema = OFF")
        return connection


def _load_authority_policy(path: Path) -> _AuthorityPolicy:
    try:
        data = tomllib.loads(_read_owner_policy_file(path).decode("ascii"))
    except (
        OSError,
        UnicodeError,
        tomllib.TOMLDecodeError,
        RecursionError,
        GuardianMembershipTransitionError,
    ):
        raise GuardianMembershipTransitionError() from None
    if not isinstance(data, dict) or set(data) != _POLICY_FIELDS:
        raise GuardianMembershipTransitionError()
    if (
        type(data["schema_version"]) is not int
        or data["schema_version"] != MEMBERSHIP_AUTHORITY_POLICY_SCHEMA_VERSION
        or type(data["network_id"]) is not str
        or not _is_epoch(data["bootstrap_epoch"])
    ):
        raise GuardianMembershipTransitionError()
    try:
        validate_network_id(data["network_id"])
        key = _decode_fixed_hex_32(data["authority_xonly_public_key"])
        PublicKeyXOnly(key)
    except ValueError:
        raise GuardianMembershipTransitionError() from None
    return _AuthorityPolicy(
        network_id=data["network_id"],
        authority_xonly_public_key=key,
        bootstrap_epoch=data["bootstrap_epoch"],
        bootstrap_membership_source_sha256=_decode_fixed_hex_32(
            data["bootstrap_membership_source_sha256"]
        ),
        bootstrap_membership_source_path=_canonical_absolute_path(
            data["bootstrap_membership_source_path"]
        ),
        ledger_path=_canonical_absolute_path(data["ledger_path"]),
    )


def _parse_transition(wire: bytes) -> _ParsedTransition:
    if type(wire) is not bytes or not 0 < len(wire) <= MAX_MEMBERSHIP_TRANSITION_BYTES:
        raise GuardianMembershipTransitionError()
    try:
        data = json.loads(wire.decode("ascii"), object_pairs_hook=_unique_object)
    except (
        UnicodeError,
        json.JSONDecodeError,
        RecursionError,
        GuardianMembershipTransitionError,
    ):
        raise GuardianMembershipTransitionError() from None
    if type(data) is not dict or tuple(data) != _TRANSITION_FIELDS:
        raise GuardianMembershipTransitionError()
    if (
        type(data["schema_version"]) is not int
        or data["schema_version"] != MEMBERSHIP_TRANSITION_SCHEMA_VERSION
        or type(data["protocol_id"]) is not str
        or data["protocol_id"] != MEMBERSHIP_TRANSITION_PROTOCOL_ID
        or type(data["network_id"]) is not str
        or not _is_epoch(data["previous_epoch"])
        or not _is_epoch(data["next_epoch"])
        or data["next_epoch"] <= data["previous_epoch"]
        or not _is_time(data["not_before_ms"])
        or not _is_time(data["not_after_ms"])
        or not 0
        < data["not_after_ms"] - data["not_before_ms"]
        <= MAX_MEMBERSHIP_TRANSITION_WINDOW_MS
    ):
        raise GuardianMembershipTransitionError()
    try:
        validate_network_id(data["network_id"])
    except ValueError:
        raise GuardianMembershipTransitionError() from None
    previous_digest = _decode_fixed_hex_32(data["previous_membership_source_sha256"])
    next_digest = _decode_fixed_hex_32(data["next_membership_source_sha256"])
    nonce = _decode_fixed_hex_32(data["nonce"])
    payload_digest = _decode_fixed_hex_32(data["payload_digest"])
    signature = _decode_fixed_hex_64(data["signature"])
    canonical = json.dumps(data, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
    if canonical != wire:
        raise GuardianMembershipTransitionError()
    unsigned = {name: data[name] for name in _UNSIGNED_TRANSITION_FIELDS}
    unsigned_wire = json.dumps(
        unsigned, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    expected_digest = hashlib.sha256(
        MEMBERSHIP_TRANSITION_DIGEST_DOMAIN
        + len(unsigned_wire).to_bytes(4, byteorder="big", signed=False)
        + unsigned_wire
    ).digest()
    if payload_digest != expected_digest:
        raise GuardianMembershipTransitionError()
    transition_id = hashlib.sha256(
        _TRANSITION_ID_DOMAIN
        + len(wire).to_bytes(4, byteorder="big", signed=False)
        + wire
    ).digest()
    return _ParsedTransition(
        wire=wire,
        transition_id=transition_id,
        network_id=data["network_id"],
        previous_epoch=data["previous_epoch"],
        previous_source_digest=previous_digest,
        next_epoch=data["next_epoch"],
        next_source_digest=next_digest,
        not_before_ms=data["not_before_ms"],
        not_after_ms=data["not_after_ms"],
        nonce=nonce,
        payload_digest=payload_digest,
        signature=signature,
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GuardianMembershipTransitionError()
        result[key] = value
    return result


def _decode_fixed_hex_32(value: object) -> bytes:
    if type(value) is not str or _FIXED_HEX_32.fullmatch(value) is None:
        raise GuardianMembershipTransitionError()
    return bytes.fromhex(value)


def _decode_fixed_hex_64(value: object) -> bytes:
    if type(value) is not str or _FIXED_HEX_64.fullmatch(value) is None:
        raise GuardianMembershipTransitionError()
    return bytes.fromhex(value)


def _is_epoch(value: object) -> bool:
    return type(value) is int and 0 <= value <= MAX_MEMBERSHIP_EPOCH


def _is_time(value: object) -> bool:
    return type(value) is int and 1 <= value <= MAX_MEMBERSHIP_TRANSITION_TIME_MS


def _canonical_absolute_path(value: object) -> Path:
    if type(value) is not str or not value:
        raise GuardianMembershipTransitionError()
    path = Path(value)
    if (
        not path.is_absolute()
        or path.name in {"", ".", ".."}
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise GuardianMembershipTransitionError()
    return path


def _read_owner_policy_file(path: Path) -> bytes:
    if (
        os.name != "posix"
        or not hasattr(os, "getuid")
        or not hasattr(os, "O_NOFOLLOW")
        or not isinstance(path, Path)
        or type(path) not in (Path, PosixPath, WindowsPath)
        or not path.is_absolute()
        or path.name in {"", ".", ".."}
        or ".." in path.parts
    ):
        raise GuardianMembershipTransitionError()
    try:
        parent = path.parent.resolve(strict=True)
        parent_stat = parent.stat()
        before = path.lstat()
        candidate = parent / path.name
        if (
            candidate != path
            or not _is_owner_only_directory(parent_stat)
            or not _is_owner_only_policy(before)
        ):
            raise GuardianMembershipTransitionError()
        descriptor = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(descriptor)
            if (
                before.st_dev != opened.st_dev
                or before.st_ino != opened.st_ino
                or before.st_size != opened.st_size
                or not _is_owner_only_policy(opened)
            ):
                raise GuardianMembershipTransitionError()
            chunks: list[bytes] = []
            remaining = MAX_MEMBERSHIP_AUTHORITY_POLICY_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 64 * 1_024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            contents = b"".join(chunks)
        finally:
            os.close(descriptor)
    except (OSError, ValueError):
        raise GuardianMembershipTransitionError() from None
    if len(contents) != before.st_size or not contents:
        raise GuardianMembershipTransitionError()
    return contents


def _prepare_ledger_path(path: Path) -> Path:
    if (
        os.name != "posix"
        or not isinstance(path, Path)
        or not path.is_absolute()
        or path.name in {"", ".", ".."}
        or ".." in path.parts
    ):
        raise GuardianMembershipTransitionError()
    try:
        parent = path.parent.resolve(strict=True)
        parent_stat = parent.stat()
    except OSError:
        raise GuardianMembershipTransitionError() from None
    candidate = parent / path.name
    if candidate != path or not _is_owner_only_directory(parent_stat):
        raise GuardianMembershipTransitionError()
    try:
        current = candidate.lstat()
    except FileNotFoundError:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW
        try:
            descriptor = os.open(candidate, flags, 0o600)
        except OSError:
            raise GuardianMembershipTransitionError() from None
        os.close(descriptor)
        current = candidate.lstat()
    except OSError:
        raise GuardianMembershipTransitionError() from None
    if (
        not stat.S_ISREG(current.st_mode)
        or current.st_uid != os.getuid()
        or stat.S_IMODE(current.st_mode) != 0o600
    ):
        raise GuardianMembershipTransitionError()
    return candidate


def _is_owner_only_directory(current: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(current.st_mode)
        and current.st_uid == os.getuid()
        and not current.st_mode & 0o077
    )


def _is_owner_only_policy(current: os.stat_result) -> bool:
    return (
        stat.S_ISREG(current.st_mode)
        and current.st_uid == os.getuid()
        and not current.st_mode & 0o077
        and not current.st_mode & 0o7000
        and 0 < current.st_size <= MAX_MEMBERSHIP_AUTHORITY_POLICY_BYTES
    )


def _table_shape(
    connection: sqlite3.Connection, table: str
) -> tuple[tuple[str, str, int, int], ...]:
    rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
    return tuple((str(row[1]), str(row[2]), int(row[3]), int(row[5])) for row in rows)


def _is_strict_table(connection: sqlite3.Connection, table: str, columns: int) -> bool:
    rows = connection.execute(f"PRAGMA table_list({table})").fetchall()
    return (
        len(rows) == 1
        and rows[0][2] == "table"
        and rows[0][3] == columns
        and rows[0][5] == 1
    )


def _unique_index_columns(
    connection: sqlite3.Connection, table: str
) -> set[tuple[str, ...]]:
    result: set[tuple[str, ...]] = set()
    for row in connection.execute(f"PRAGMA index_list({table})").fetchall():
        if row[2] != 1 or row[4] != 0:
            continue
        columns = connection.execute(f"PRAGMA index_info({row[1]})").fetchall()
        result.add(tuple(str(column[2]) for column in columns))
    return result


def _raise_operational_error(error: sqlite3.OperationalError) -> NoReturn:
    error_code = getattr(error, "sqlite_errorcode", None)
    if type(error_code) is int and error_code & 0xFF in {
        sqlite3.SQLITE_BUSY,
        sqlite3.SQLITE_LOCKED,
    }:
        raise GuardianMembershipTransitionBusyError() from None
    raise GuardianMembershipTransitionError() from None
