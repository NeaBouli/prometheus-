"""Local durable one-time consumption of verified Observable Approvals."""

from __future__ import annotations

import os
import sqlite3
import stat
import tomllib
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Final, NoReturn

from jaeger.observable_approval import (
    FIXED_HASH_BYTES,
    UINT64_MAX,
    ObservableApprovalContext,
    ObservableApprovalError,
    VerifiedObservableApproval,
    verify_observable_approval,
)
from jaeger.threat_observable import validate_network_id

CONSUMPTION_POLICY_SCHEMA_VERSION: Final[int] = 1
MAX_CONSUMPTION_POLICY_BYTES: Final[int] = 4_096
_SQLITE_SCHEMA_VERSION: Final[int] = 1
_POLICY_FIELDS = {
    "schema_version",
    "network_id",
    "approver_xonly_public_key",
    "recipient_scope",
    "ledger_path",
}


class ObservableApprovalConsumptionError(ValueError):
    """Closed failure for policy, verification, or durable consumption."""

    def __init__(self) -> None:
        super().__init__("observable approval was not consumed")


class ObservableApprovalReplayError(ObservableApprovalConsumptionError):
    """The approval identity or authority-bound nonce was already consumed."""


class ObservableApprovalBusyError(ObservableApprovalConsumptionError):
    """The durable boundary is temporarily unavailable without consumption."""


@dataclass(frozen=True)
class ObservableApprovalPolicy:
    """One owner-configured network, authority key, and opaque recipient scope."""

    network_id: str
    approver_xonly_public_key: bytes
    recipient_scope: bytes
    ledger_path: Path


@dataclass(frozen=True)
class ObservableApprovalConsumptionReceipt:
    """Data-only local receipt; it grants no downstream authority."""

    approval_id: bytes
    observable_commitment: bytes
    consumed_at: int


def load_observable_approval_policy(path: Path) -> ObservableApprovalPolicy:
    """Load one exact-schema policy from an owner-only regular TOML file."""
    try:
        policy_path = _validate_owner_policy_path(path)
        data = tomllib.loads(policy_path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        raise ObservableApprovalConsumptionError() from None
    if not isinstance(data, dict) or set(data) != _POLICY_FIELDS:
        raise ObservableApprovalConsumptionError()
    if (
        type(data["schema_version"]) is not int  # pylint: disable=C0123
        or data["schema_version"] != CONSUMPTION_POLICY_SCHEMA_VERSION
    ):
        raise ObservableApprovalConsumptionError()

    network_id = data["network_id"]
    if type(network_id) is not str:  # pylint: disable=C0123
        raise ObservableApprovalConsumptionError()
    try:
        validate_network_id(network_id)
    except ValueError:
        raise ObservableApprovalConsumptionError() from None

    ledger_path = _canonical_absolute_path(data["ledger_path"])
    return ObservableApprovalPolicy(
        network_id=network_id,
        approver_xonly_public_key=_decode_fixed_lower_hex(
            data["approver_xonly_public_key"]
        ),
        recipient_scope=_decode_fixed_lower_hex(data["recipient_scope"]),
        ledger_path=ledger_path,
    )


class _ObservableApprovalLedger:  # pylint: disable=too-few-public-methods
    """Owner-only SQLite state for approval and authority-nonce replay control."""

    def __init__(self, path: Path) -> None:
        self.path = _prepare_ledger_path(path)
        try:
            with closing(self._connect()) as connection:
                with connection:
                    version = connection.execute("PRAGMA user_version").fetchone()[0]
                    if version not in (0, _SQLITE_SCHEMA_VERSION):
                        raise ObservableApprovalConsumptionError()
                    connection.execute("""
                        CREATE TABLE IF NOT EXISTS approval_consumptions (
                            approval_id BLOB PRIMARY KEY
                                CHECK(length(approval_id) = 32),
                            approver_xonly_public_key BLOB NOT NULL
                                CHECK(length(approver_xonly_public_key) = 32),
                            approval_nonce BLOB NOT NULL
                                CHECK(length(approval_nonce) = 32),
                            observable_commitment BLOB NOT NULL
                                CHECK(length(observable_commitment) = 32),
                            recipient_scope BLOB NOT NULL
                                CHECK(length(recipient_scope) = 32),
                            network_id TEXT NOT NULL,
                            not_before INTEGER NOT NULL,
                            expires_at INTEGER NOT NULL,
                            consumed_at INTEGER NOT NULL,
                            UNIQUE (approver_xonly_public_key, approval_nonce)
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
                    connection.execute(
                        f"PRAGMA user_version = {_SQLITE_SCHEMA_VERSION}"
                    )
                    self._validate_schema(connection)
        except ObservableApprovalConsumptionError:
            raise
        except sqlite3.OperationalError as exc:
            _raise_operational_error(exc)
        except (sqlite3.Error, OSError):
            raise ObservableApprovalConsumptionError() from None

    def consume(
        self,
        verified: VerifiedObservableApproval,
        consumed_at: int,
    ) -> ObservableApprovalConsumptionReceipt:
        """Atomically persist one result produced in the enclosing trusted call."""
        if (
            type(verified) is not VerifiedObservableApproval  # pylint: disable=C0123
            or not _is_timestamp(consumed_at)
            or consumed_at < verified.not_before
            or consumed_at > verified.expires_at
        ):
            raise ObservableApprovalConsumptionError()
        try:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute("BEGIN IMMEDIATE")
                    self._advance_time(connection, consumed_at)
                    connection.execute(
                        """
                        INSERT INTO approval_consumptions (
                            approval_id, approver_xonly_public_key, approval_nonce,
                            observable_commitment, recipient_scope, network_id,
                            not_before, expires_at, consumed_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            verified.approval_id,
                            verified.approver_xonly_public_key,
                            verified.approval_nonce,
                            verified.observable_commitment,
                            verified.recipient_scope,
                            verified.network_id,
                            verified.not_before,
                            verified.expires_at,
                            consumed_at,
                        ),
                    )
        except sqlite3.IntegrityError:
            try:
                with closing(self._connect()) as connection:
                    replay = connection.execute(
                        """
                        SELECT 1 FROM approval_consumptions
                        WHERE approval_id = ?
                           OR (
                               approver_xonly_public_key = ?
                               AND approval_nonce = ?
                           )
                        """,
                        (
                            verified.approval_id,
                            verified.approver_xonly_public_key,
                            verified.approval_nonce,
                        ),
                    ).fetchone()
            except sqlite3.OperationalError as exc:
                _raise_operational_error(exc)
            except sqlite3.Error:
                raise ObservableApprovalConsumptionError() from None
            if replay is not None:
                raise ObservableApprovalReplayError() from None
            raise ObservableApprovalConsumptionError() from None
        except sqlite3.OperationalError as exc:
            _raise_operational_error(exc)
        except sqlite3.Error:
            raise ObservableApprovalConsumptionError() from None
        return ObservableApprovalConsumptionReceipt(
            approval_id=verified.approval_id,
            observable_commitment=verified.observable_commitment,
            consumed_at=consumed_at,
        )

    @staticmethod
    def _advance_time(connection: sqlite3.Connection, consumed_at: int) -> None:
        row = connection.execute(
            "SELECT high_water_seconds FROM ledger_state WHERE singleton = 1"
        ).fetchone()
        if row is None or type(row[0]) is not int:  # pylint: disable=C0123
            raise ObservableApprovalConsumptionError()
        if consumed_at < row[0]:
            raise ObservableApprovalReplayError()
        connection.execute(
            "UPDATE ledger_state SET high_water_seconds = ? WHERE singleton = 1",
            (consumed_at,),
        )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=0.25, isolation_level=None)
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA trusted_schema = OFF")
        return connection

    @staticmethod
    def _validate_schema(connection: sqlite3.Connection) -> None:
        expected_consumptions = (
            ("approval_id", "BLOB", 1, 1),
            ("approver_xonly_public_key", "BLOB", 1, 0),
            ("approval_nonce", "BLOB", 1, 0),
            ("observable_commitment", "BLOB", 1, 0),
            ("recipient_scope", "BLOB", 1, 0),
            ("network_id", "TEXT", 1, 0),
            ("not_before", "INTEGER", 1, 0),
            ("expires_at", "INTEGER", 1, 0),
            ("consumed_at", "INTEGER", 1, 0),
        )
        expected_state = (
            ("singleton", "INTEGER", 0, 1),
            ("high_water_seconds", "INTEGER", 1, 0),
        )
        if (
            _table_shape(connection, "approval_consumptions") != expected_consumptions
            or _table_shape(connection, "ledger_state") != expected_state
            or not _is_strict_table(connection, "approval_consumptions", 9)
            or not _is_strict_table(connection, "ledger_state", 2)
            or _unique_index_columns(connection, "approval_consumptions")
            != {
                ("approval_id",),
                ("approver_xonly_public_key", "approval_nonce"),
            }
        ):
            raise ObservableApprovalConsumptionError()


class ObservableApprovalConsumptionService:  # pylint: disable=too-few-public-methods
    """Verify and consume locally without triggering any external side effect."""

    def __init__(self, policy_path: Path) -> None:
        self._policy = load_observable_approval_policy(policy_path)
        self._ledger = _ObservableApprovalLedger(self._policy.ledger_path)

    def consume(
        self,
        approval_wire: bytes,
        bundle_wire: bytes,
        *,
        report_nonce: bytes,
        current_time: int,
    ) -> ObservableApprovalConsumptionReceipt:
        """Verify from trusted inputs and durably consume in the same call path."""
        if (
            type(report_nonce) is not bytes  # pylint: disable=C0123
            or len(report_nonce) != FIXED_HASH_BYTES
            or not _is_timestamp(current_time)
        ):
            raise ObservableApprovalConsumptionError()
        context = ObservableApprovalContext(
            report_nonce=report_nonce,
            approver_xonly_public_key=self._policy.approver_xonly_public_key,
            recipient_scope=self._policy.recipient_scope,
            network_id=self._policy.network_id,
            current_time=current_time,
        )
        try:
            verified = verify_observable_approval(approval_wire, bundle_wire, context)
        except ObservableApprovalError:
            raise ObservableApprovalConsumptionError() from None
        return self._ledger.consume(verified, current_time)


def _validate_owner_policy_path(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ObservableApprovalConsumptionError()
    try:
        parent = path.parent.resolve(strict=True)
        parent_stat = parent.stat()
        current = path.lstat()
    except OSError:
        raise ObservableApprovalConsumptionError() from None
    candidate = parent / path.name
    if (
        candidate != path
        or not _is_safe_policy_parent(parent_stat)
        or not _is_safe_policy_file(current)
    ):
        raise ObservableApprovalConsumptionError()
    return candidate


def _prepare_ledger_path(path: Path) -> Path:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise ObservableApprovalConsumptionError()
    try:
        parent = path.parent.resolve(strict=True)
        parent_stat = parent.stat()
    except OSError:
        raise ObservableApprovalConsumptionError() from None
    candidate = parent / path.name
    if (
        candidate != path
        or not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != os.getuid()
        or parent_stat.st_mode & 0o077
    ):
        raise ObservableApprovalConsumptionError()
    try:
        current = candidate.lstat()
    except FileNotFoundError:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(candidate, flags, 0o600)
        except OSError:
            raise ObservableApprovalConsumptionError() from None
        os.close(descriptor)
    except OSError:
        raise ObservableApprovalConsumptionError() from None
    else:
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_uid != os.getuid()
            or current.st_mode & 0o177
            or current.st_mode & 0o600 != 0o600
        ):
            raise ObservableApprovalConsumptionError()
    return candidate


def _canonical_absolute_path(value: object) -> Path:
    if type(value) is not str or not value:  # pylint: disable=C0123
        raise ObservableApprovalConsumptionError()
    path = Path(value)
    if (
        not path.is_absolute()
        or path.name in {"", ".", ".."}
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise ObservableApprovalConsumptionError()
    return path


def _decode_fixed_lower_hex(value: object) -> bytes:
    if (
        type(value) is not str  # pylint: disable=C0123
        or len(value) != FIXED_HASH_BYTES * 2
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ObservableApprovalConsumptionError()
    return bytes.fromhex(value)


def _is_safe_policy_parent(current: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(current.st_mode)
        and current.st_uid == os.getuid()
        and not current.st_mode & 0o077
    )


def _is_safe_policy_file(current: os.stat_result) -> bool:
    return (
        stat.S_ISREG(current.st_mode)
        and current.st_uid == os.getuid()
        and not current.st_mode & 0o077
        and not current.st_mode & 0o7000
        and 0 < current.st_size <= MAX_CONSUMPTION_POLICY_BYTES
    )


def _is_timestamp(value: object) -> bool:
    return (
        type(value) is int  # pylint: disable=unidiomatic-typecheck
        and 0 < value <= UINT64_MAX
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
    if getattr(error, "sqlite_errorcode", None) in {
        sqlite3.SQLITE_BUSY,
        sqlite3.SQLITE_LOCKED,
    }:
        raise ObservableApprovalBusyError() from None
    raise ObservableApprovalConsumptionError() from None
