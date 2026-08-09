"""Local durable one-time consumption of verified Observable Approvals.

Governed ledgers additionally carry one recoverable local outbox: a governed
consumption with the durable outbox enabled atomically enqueues the canonical
statement and bundle bindings in the same transaction as the authority
snapshot, replay high-water mark, and consumption row. Records are leased
single-winner through ``ObservableApprovalOutbox`` and may be removed only by
an atomic durable non-actionable completion.

Governed durable-outbox consumptions also retain one permanent database-level
statement/approval/commitment pairing after outbox and result retention.
"""

# Exact built-in types are protocol requirements.
# pylint: disable=unidiomatic-typecheck,too-many-lines
# pylint: disable=too-many-arguments,too-many-positional-arguments
# pylint: disable=too-many-boolean-expressions,too-many-branches
# pylint: disable=too-many-instance-attributes

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
import tomllib
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path, PosixPath, WindowsPath
from typing import Final, NoReturn

from jaeger.observable_approval import (
    FIXED_HASH_BYTES,
    UINT64_MAX,
    ObservableApprovalContext,
    ObservableApprovalError,
    VerifiedObservableApproval,
    verify_observable_approval,
)
from jaeger.outbox_retention_policy import (
    OutboxRetentionPolicy,
    OutboxRetentionPolicyError,
    load_outbox_retention_policy,
)
from jaeger.threat_hint_v2_governance import (
    ThreatHintV2GovernancePolicy,
    ThreatHintV2GovernancePolicyError,
    load_threat_hint_v2_governance_policy,
)
from jaeger.threat_hint_v2_statement import (
    MAX_CANONICAL_V2_STATEMENT_BYTES,
    ThreatHintV2Statement,
    ThreatHintV2StatementError,
)
from jaeger.threat_observable import (
    MAX_CANONICAL_BYTES,
    MAX_OBSERVABLES,
    ObservableBundle,
    ObservableKind,
    validate_network_id,
)

CONSUMPTION_POLICY_SCHEMA_VERSION: Final[int] = 1
MAX_CONSUMPTION_POLICY_BYTES: Final[int] = 4_096
_SQLITE_SCHEMA_VERSION_LEGACY: Final[int] = 1
_SQLITE_SCHEMA_VERSION_GOVERNED_V2: Final[int] = 2
_SQLITE_SCHEMA_VERSION_GOVERNED_V3: Final[int] = 3
_SQLITE_SCHEMA_VERSION_GOVERNED_V4: Final[int] = 4
_SQLITE_SCHEMA_VERSION_GOVERNED: Final[int] = 5
MAX_OUTBOX_LEASE_SECONDS: Final[int] = 300
ANALYSIS_RESULT_SCHEMA_VERSION: Final[int] = 1
ANALYSIS_RESULT_KIND: Final[str] = "non_actionable_local_v1"
MAX_CANONICAL_ANALYSIS_RESULT_BYTES: Final[int] = 1_024
ANALYSIS_INPUT_IDENTITY_DOMAIN: Final[bytes] = (
    b"prometheus-observable-analysis-input-v1\x00"
)
ANALYSIS_RESULT_DIGEST_DOMAIN: Final[bytes] = (
    b"prometheus-observable-analysis-result-v1\x00"
)
COMPLETION_TOKEN_DIGEST_DOMAIN: Final[bytes] = (
    b"prometheus-observable-analysis-completion-v1\x00"
)
_ANALYZER_ID_RE = re.compile(r"[a-z0-9][a-z0-9_]{0,63}")
_ANALYSIS_RESULT_FIELDS = (
    "schema_version",
    "result_kind",
    "analyzer_id",
    "approval_id",
    "input_identity",
    "statement_digest",
    "observable_commitment",
    "observable_count",
)
_POLICY_FIELDS = {
    "schema_version",
    "network_id",
    "approver_xonly_public_key",
    "recipient_scope",
    "ledger_path",
}


class ObservableApprovalConsumptionError(ValueError):
    """Closed failure for policy, verification, or durable consumption."""

    _MESSAGE = "observable approval was not consumed"

    def __init__(self) -> None:
        super().__init__(self._MESSAGE)


class ObservableApprovalReplayError(ObservableApprovalConsumptionError):
    """The approval identity or authority-bound nonce was already consumed."""


class ObservableApprovalBusyError(ObservableApprovalConsumptionError):
    """The durable boundary is temporarily unavailable without consumption."""


class ObservableApprovalGovernanceCandidateError(ObservableApprovalConsumptionError):
    """A signed approval or bundle violates the active governance policy."""


class ObservableApprovalGovernanceUnavailableError(ObservableApprovalConsumptionError):
    """The durable authority snapshot is stale, equivocated, or unavailable."""


class ObservableApprovalOutboxError(ObservableApprovalConsumptionError):
    """Closed failure for outbox capacity, enqueue, claim, or acknowledge."""

    _MESSAGE = "observable approval outbox failure"


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


@dataclass(frozen=True, init=False, repr=False, eq=False)
class ObservableApprovalOutboxClaim:
    """Immutable single-winner lease on one pending outbox record.

    Direct construction is disabled; ``ObservableApprovalOutbox.claim`` is the
    only supported construction path. The claim carries only the fields a
    later local processing step needs: the approval binding, the canonical
    bundle wire, the lease token required for acknowledge, and the lease
    expiry. It is not serializable and grants no authority.
    """

    approval_id: bytes
    observable_commitment: bytes
    bundle_wire: bytes
    statement_wire: bytes
    statement_digest: bytes
    report_nonce: bytes
    lease_token: bytes
    lease_expires_at: int
    input_identity: bytes

    def __init__(self) -> None:
        raise TypeError("direct outbox claim construction is disabled")

    def __reduce__(self) -> object:
        raise TypeError("outbox claim is not serializable")


@dataclass(frozen=True, init=False, repr=False, eq=False)
class ObservableAnalysisCompletion:
    """Immutable receipt for one durable non-actionable completion."""

    approval_id: bytes
    result_digest: bytes
    input_identity: bytes
    completed_at: int
    retention_deadline: int

    def __init__(self) -> None:
        raise TypeError(
            "direct observable analysis completion construction is disabled"
        )

    def __reduce__(self) -> object:
        raise TypeError("observable analysis completion is not serializable")


@dataclass(frozen=True, init=False, repr=False, eq=False)
class ObservableAnalysisStoredResult:
    """Immutable owner-local result recovered from durable storage."""

    approval_id: bytes
    result_wire: bytes
    result_digest: bytes
    input_identity: bytes
    completed_at: int
    retention_deadline: int

    def __init__(self) -> None:
        raise TypeError("direct observable analysis result construction is disabled")

    def __reduce__(self) -> object:
        raise TypeError("observable analysis result is not serializable")


@dataclass(frozen=True)
class _GovernanceBinding:
    """One immutable, cross-policy checked governance snapshot."""

    policy: ThreatHintV2GovernancePolicy
    retention: OutboxRetentionPolicy
    promotion_policy_sha256: bytes


def load_observable_approval_policy(path: Path) -> ObservableApprovalPolicy:
    """Load one exact-schema policy from an owner-only regular TOML file."""
    try:
        data = tomllib.loads(_read_owner_policy_file(path).decode("ascii"))
    except (
        OSError,
        UnicodeError,
        tomllib.TOMLDecodeError,
        RecursionError,
    ):
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

    def __init__(
        self,
        path: Path,
        governance: _GovernanceBinding | None = None,
        durable_outbox: bool = False,
    ) -> None:
        if type(durable_outbox) is not bool or (  # pylint: disable=C0123
            durable_outbox and governance is None
        ):
            raise ObservableApprovalConsumptionError()
        self.path = _prepare_ledger_path(path)
        self._governance = governance
        self._outbox_enabled = durable_outbox
        try:
            with closing(self._connect()) as connection:
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    version = connection.execute("PRAGMA user_version").fetchone()[0]
                    self._initialize_schema(connection, version)
                    connection.commit()
                except BaseException:
                    connection.rollback()
                    raise
        except ObservableApprovalConsumptionError:
            raise
        except sqlite3.OperationalError as exc:
            _raise_operational_error(exc)
        except (sqlite3.Error, OSError):
            raise ObservableApprovalConsumptionError() from None

    def _initialize_schema(
        self,
        connection: sqlite3.Connection,
        version: int,
    ) -> None:
        governed = self._governance is not None
        if governed:
            if version not in (
                0,
                _SQLITE_SCHEMA_VERSION_LEGACY,
                _SQLITE_SCHEMA_VERSION_GOVERNED_V2,
                _SQLITE_SCHEMA_VERSION_GOVERNED_V3,
                _SQLITE_SCHEMA_VERSION_GOVERNED_V4,
                _SQLITE_SCHEMA_VERSION_GOVERNED,
            ):
                raise ObservableApprovalConsumptionError()
        elif version not in (0, _SQLITE_SCHEMA_VERSION_LEGACY):
            raise ObservableApprovalConsumptionError()

        if version == _SQLITE_SCHEMA_VERSION_LEGACY:
            self._validate_schema(connection, governed=False)
        if governed and version in (0, _SQLITE_SCHEMA_VERSION_LEGACY):
            if _table_shape(connection, "authority_state"):
                raise ObservableApprovalConsumptionError()
        if (
            governed
            and version
            not in (
                _SQLITE_SCHEMA_VERSION_GOVERNED_V3,
                _SQLITE_SCHEMA_VERSION_GOVERNED_V4,
                _SQLITE_SCHEMA_VERSION_GOVERNED,
            )
            and _table_shape(connection, "approval_outbox")
        ):
            raise ObservableApprovalConsumptionError()
        if (
            governed
            and version
            not in (
                _SQLITE_SCHEMA_VERSION_GOVERNED_V4,
                _SQLITE_SCHEMA_VERSION_GOVERNED,
            )
            and _table_shape(connection, "observable_analysis_results")
        ):
            raise ObservableApprovalConsumptionError()
        if version != _SQLITE_SCHEMA_VERSION_GOVERNED and _table_shape(
            connection, "threat_hint_v2_pairings"
        ):
            raise ObservableApprovalConsumptionError()
        if version == 0:
            self._create_legacy_schema(connection)
        if governed:
            if version == _SQLITE_SCHEMA_VERSION_GOVERNED:
                self._validate_schema(connection, governed=True)
                return
            if version == _SQLITE_SCHEMA_VERSION_GOVERNED_V3:
                self._validate_schema(
                    connection,
                    governed=True,
                    governed_version=_SQLITE_SCHEMA_VERSION_GOVERNED_V3,
                )
                pending = connection.execute(
                    "SELECT COUNT(*) FROM approval_outbox"
                ).fetchone()
                if (
                    pending is None
                    or type(pending[0]) is not int  # pylint: disable=C0123
                    or pending[0] != 0
                ):
                    raise ObservableApprovalConsumptionError()
                connection.execute("DROP TABLE approval_outbox")
            if version == _SQLITE_SCHEMA_VERSION_GOVERNED_V4:
                self._validate_schema(
                    connection,
                    governed=True,
                    governed_version=_SQLITE_SCHEMA_VERSION_GOVERNED_V4,
                )
                pending_outbox = connection.execute(
                    "SELECT COUNT(*) FROM approval_outbox"
                ).fetchone()
                pending_results = connection.execute(
                    "SELECT COUNT(*) FROM observable_analysis_results"
                ).fetchone()
                if (
                    pending_outbox is None
                    or pending_results is None
                    or type(pending_outbox[0]) is not int
                    or type(pending_results[0]) is not int
                    or pending_outbox[0] != 0
                    or pending_results[0] != 0
                ):
                    raise ObservableApprovalConsumptionError()
            connection.execute("""
                CREATE TABLE IF NOT EXISTS authority_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    authority_epoch INTEGER NOT NULL CHECK (authority_epoch >= 1),
                    governance_policy_sha256 BLOB NOT NULL
                        CHECK(length(governance_policy_sha256) = 32),
                    retention_policy_sha256 BLOB NOT NULL
                        CHECK(length(retention_policy_sha256) = 32),
                    promotion_policy_sha256 BLOB NOT NULL
                        CHECK(length(promotion_policy_sha256) = 32),
                    network_id TEXT NOT NULL,
                    approver_xonly_public_key BLOB NOT NULL
                        CHECK(length(approver_xonly_public_key) = 32),
                    recipient_scope BLOB NOT NULL
                        CHECK(length(recipient_scope) = 32),
                    authority_not_before INTEGER NOT NULL,
                    authority_not_after INTEGER NOT NULL
                ) STRICT
                """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS approval_outbox (
                    approval_id BLOB PRIMARY KEY
                        CHECK(length(approval_id) = 32),
                    observable_commitment BLOB NOT NULL
                        CHECK(length(observable_commitment) = 32),
                    bundle_wire BLOB NOT NULL
                        CHECK(length(bundle_wire) >= 1),
                    statement_wire BLOB NOT NULL
                        CHECK(length(statement_wire) >= 1),
                    statement_digest BLOB NOT NULL
                        CHECK(length(statement_digest) = 32),
                    report_nonce BLOB NOT NULL
                        CHECK(length(report_nonce) = 32),
                    enqueued_at INTEGER NOT NULL
                        CHECK(enqueued_at >= 1),
                    retention_deadline INTEGER NOT NULL
                        CHECK(retention_deadline >= enqueued_at),
                    lease_token BLOB
                        CHECK(lease_token IS NULL OR length(lease_token) = 32),
                    lease_expires_at INTEGER
                        CHECK(lease_expires_at IS NULL OR lease_expires_at >= 1),
                    CHECK ((lease_token IS NULL) = (lease_expires_at IS NULL)),
                    CHECK (
                        lease_expires_at IS NULL
                        OR lease_expires_at <= retention_deadline
                    )
                ) STRICT
                """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS observable_analysis_results (
                    approval_id BLOB PRIMARY KEY
                        CHECK(length(approval_id) = 32)
                        REFERENCES approval_consumptions(approval_id),
                    result_wire BLOB NOT NULL
                        CHECK(length(result_wire) >= 1),
                    result_digest BLOB NOT NULL
                        CHECK(length(result_digest) = 32),
                    input_identity BLOB NOT NULL
                        CHECK(length(input_identity) = 32),
                    completion_token_digest BLOB NOT NULL
                        CHECK(length(completion_token_digest) = 32),
                    completed_at INTEGER NOT NULL
                        CHECK(completed_at >= 1),
                    retention_deadline INTEGER NOT NULL
                        CHECK(retention_deadline >= completed_at)
                ) STRICT
                """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS threat_hint_v2_pairings (
                    statement_digest BLOB PRIMARY KEY
                        CHECK(length(statement_digest) = 32),
                    approval_id BLOB NOT NULL UNIQUE
                        CHECK(length(approval_id) = 32)
                        REFERENCES approval_consumptions(approval_id),
                    observable_commitment BLOB NOT NULL UNIQUE
                        CHECK(length(observable_commitment) = 32),
                    network_id TEXT NOT NULL,
                    consumed_at INTEGER NOT NULL CHECK(consumed_at >= 1)
                ) STRICT
                """)
            connection.execute(
                f"PRAGMA user_version = {_SQLITE_SCHEMA_VERSION_GOVERNED}"
            )
            self._validate_schema(connection, governed=True)
        else:
            connection.execute(f"PRAGMA user_version = {_SQLITE_SCHEMA_VERSION_LEGACY}")
            self._validate_schema(connection, governed=False)

    @staticmethod
    def _create_legacy_schema(connection: sqlite3.Connection) -> None:
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

    def consume(
        self,
        verified: VerifiedObservableApproval,
        consumed_at: int,
    ) -> ObservableApprovalConsumptionReceipt:
        """Atomically persist one result produced in the enclosing trusted call."""
        return self._consume(
            verified,
            consumed_at,
            governance=None,
            bundle_wire=None,
            statement_wire=None,
            report_nonce=None,
        )

    def consume_governed(
        self,
        verified: VerifiedObservableApproval,
        consumed_at: int,
        governance: _GovernanceBinding,
        bundle_wire: bytes,
        *,
        statement_wire: bytes | None,
        report_nonce: bytes,
    ) -> ObservableApprovalConsumptionReceipt:
        """Atomically pin/advance governance, time, and consumption together.

        When this ledger was built with the durable outbox enabled, the same
        transaction also enqueues one recoverable outbox record bound to the
        approval; any capacity or enqueue failure rolls all four states back.
        """
        if governance is not self._governance:
            raise ObservableApprovalGovernanceUnavailableError()
        if self._outbox_enabled == (statement_wire is None):
            raise ObservableApprovalOutboxError()
        return self._consume(
            verified,
            consumed_at,
            governance=governance,
            bundle_wire=bundle_wire,
            statement_wire=statement_wire,
            report_nonce=report_nonce,
        )

    def assert_authority_snapshot(self, governance: _GovernanceBinding) -> None:
        """Advisory fail-fast check; consume re-checks authoritatively."""
        if governance is not self._governance:
            raise ObservableApprovalGovernanceUnavailableError()
        try:
            with closing(self._connect()) as connection:
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                if version != _SQLITE_SCHEMA_VERSION_GOVERNED:
                    raise ObservableApprovalGovernanceUnavailableError()
                row = connection.execute("""
                    SELECT authority_epoch, governance_policy_sha256,
                           retention_policy_sha256, promotion_policy_sha256,
                           network_id, approver_xonly_public_key,
                           recipient_scope, authority_not_before,
                           authority_not_after
                    FROM authority_state WHERE singleton = 1
                    """).fetchone()
                self._validate_authority_snapshot(row, governance)
        except ObservableApprovalConsumptionError:
            raise
        except sqlite3.OperationalError as exc:
            _raise_operational_error(exc)
        except sqlite3.Error:
            raise ObservableApprovalGovernanceUnavailableError() from None

    def _consume(
        self,
        verified: VerifiedObservableApproval,
        consumed_at: int,
        governance: _GovernanceBinding | None,
        bundle_wire: bytes | None,
        statement_wire: bytes | None,
        report_nonce: bytes | None,
    ) -> ObservableApprovalConsumptionReceipt:
        if (  # pylint: disable=too-many-boolean-expressions
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
                    if governance is not None:
                        self._apply_authority_snapshot(connection, governance)
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
                    if governance is not None and self._outbox_enabled:
                        self._enqueue_outbox(
                            connection,
                            verified,
                            bundle_wire,
                            statement_wire,
                            report_nonce,
                            consumed_at,
                            governance.retention,
                        )
        except sqlite3.IntegrityError:
            statement_digest: bytes | None = None
            if (
                governance is not None
                and self._outbox_enabled
                and type(statement_wire) is bytes
                and type(report_nonce) is bytes
            ):
                try:
                    statement_digest = _validate_outbox_statement(
                        statement_wire,
                        verified.network_id,
                        observable_commitment=verified.observable_commitment,
                        report_nonce=report_nonce,
                    )
                except ObservableApprovalConsumptionError:
                    statement_digest = None
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
                    if replay is None and statement_digest is not None:
                        replay = connection.execute(
                            """
                            SELECT 1 FROM threat_hint_v2_pairings
                            WHERE statement_digest = ?
                               OR approval_id = ?
                               OR observable_commitment = ?
                            """,
                            (
                                statement_digest,
                                verified.approval_id,
                                verified.observable_commitment,
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
        except OverflowError:
            raise ObservableApprovalConsumptionError() from None
        return ObservableApprovalConsumptionReceipt(
            approval_id=verified.approval_id,
            observable_commitment=verified.observable_commitment,
            consumed_at=consumed_at,
        )

    @staticmethod
    def _validate_authority_snapshot(
        row: tuple | None,
        governance: _GovernanceBinding,
    ) -> None:
        if row is None:
            return
        if (  # pylint: disable=too-many-boolean-expressions
            len(row) != 9
            or type(row[0]) is not int  # pylint: disable=C0123
            or type(row[1]) is not bytes  # pylint: disable=C0123
            or type(row[2]) is not bytes  # pylint: disable=C0123
            or type(row[3]) is not bytes  # pylint: disable=C0123
            or type(row[4]) is not str  # pylint: disable=C0123
            or type(row[5]) is not bytes  # pylint: disable=C0123
            or type(row[6]) is not bytes  # pylint: disable=C0123
            or type(row[7]) is not int  # pylint: disable=C0123
            or type(row[8]) is not int  # pylint: disable=C0123
            or len(row[1]) != FIXED_HASH_BYTES
            or len(row[2]) != FIXED_HASH_BYTES
            or len(row[3]) != FIXED_HASH_BYTES
            or len(row[5]) != FIXED_HASH_BYTES
            or len(row[6]) != FIXED_HASH_BYTES
        ):
            raise ObservableApprovalGovernanceUnavailableError()
        policy = governance.policy
        if policy.authority_epoch < row[0] or policy.network_id != row[4]:
            raise ObservableApprovalGovernanceUnavailableError()
        # pylint: disable-next=too-many-boolean-expressions
        if policy.authority_epoch == row[0] and (
            not hmac.compare_digest(policy.policy_sha256, row[1])
            or not hmac.compare_digest(governance.retention.policy_sha256, row[2])
            or not hmac.compare_digest(governance.promotion_policy_sha256, row[3])
            or not hmac.compare_digest(policy.approver_xonly_public_key, row[5])
            or not hmac.compare_digest(policy.recipient_scope, row[6])
            or policy.authority_not_before != row[7]
            or policy.authority_not_after != row[8]
        ):
            raise ObservableApprovalGovernanceUnavailableError()
        if (
            policy.authority_epoch > row[0]
            and hmac.compare_digest(policy.approver_xonly_public_key, row[5])
            and hmac.compare_digest(policy.recipient_scope, row[6])
            and policy.authority_not_before <= row[8]
        ):
            raise ObservableApprovalGovernanceUnavailableError()

    @classmethod
    def _apply_authority_snapshot(
        cls,
        connection: sqlite3.Connection,
        governance: _GovernanceBinding,
    ) -> None:
        if (
            connection.execute("PRAGMA user_version").fetchone()[0]
            != _SQLITE_SCHEMA_VERSION_GOVERNED
        ):
            raise ObservableApprovalGovernanceUnavailableError()
        row = connection.execute("""
            SELECT authority_epoch, governance_policy_sha256,
                   retention_policy_sha256, promotion_policy_sha256,
                   network_id, approver_xonly_public_key, recipient_scope,
                   authority_not_before, authority_not_after
            FROM authority_state WHERE singleton = 1
            """).fetchone()
        cls._validate_authority_snapshot(row, governance)
        policy = governance.policy
        if row is None:
            connection.execute(
                """
                INSERT INTO authority_state (
                    singleton, authority_epoch, governance_policy_sha256,
                    retention_policy_sha256, promotion_policy_sha256,
                    network_id, approver_xonly_public_key, recipient_scope,
                    authority_not_before, authority_not_after
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    policy.authority_epoch,
                    policy.policy_sha256,
                    governance.retention.policy_sha256,
                    governance.promotion_policy_sha256,
                    policy.network_id,
                    policy.approver_xonly_public_key,
                    policy.recipient_scope,
                    policy.authority_not_before,
                    policy.authority_not_after,
                ),
            )
        elif policy.authority_epoch > row[0]:
            connection.execute(
                """
                UPDATE authority_state
                SET authority_epoch = ?, governance_policy_sha256 = ?,
                    retention_policy_sha256 = ?, promotion_policy_sha256 = ?,
                    network_id = ?, approver_xonly_public_key = ?,
                    recipient_scope = ?, authority_not_before = ?,
                    authority_not_after = ?
                WHERE singleton = 1
                """,
                (
                    policy.authority_epoch,
                    policy.policy_sha256,
                    governance.retention.policy_sha256,
                    governance.promotion_policy_sha256,
                    policy.network_id,
                    policy.approver_xonly_public_key,
                    policy.recipient_scope,
                    policy.authority_not_before,
                    policy.authority_not_after,
                ),
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

    @staticmethod
    def _enqueue_outbox(
        connection: sqlite3.Connection,
        verified: VerifiedObservableApproval,
        bundle_wire: bytes | None,
        statement_wire: bytes | None,
        report_nonce: bytes | None,
        consumed_at: int,
        retention: OutboxRetentionPolicy,
    ) -> None:
        """Clean up, check capacity, and insert inside the consume transaction.

        Retention cleanup deletes strictly by deadline: a lease can never
        extend past its record's retention deadline, so no cleanup ever
        removes an active lease. A full outbox or any insert failure raises a
        stable redacted error that rolls the whole consume transaction back
        without consuming the approval.
        """
        if (
            type(retention.max_pending_records) is not int  # pylint: disable=C0123
            or type(retention.max_retention_seconds) is not int  # pylint: disable=C0123
            or retention.max_pending_records < 1
            or retention.max_retention_seconds < 1
        ):
            raise ObservableApprovalOutboxError()
        retention_deadline = consumed_at + retention.max_retention_seconds
        if (
            type(bundle_wire) is not bytes  # pylint: disable=C0123
            or not 1 <= len(bundle_wire) <= MAX_CANONICAL_BYTES
            or type(statement_wire) is not bytes  # pylint: disable=C0123
            or type(report_nonce) is not bytes  # pylint: disable=C0123
            or len(report_nonce) != FIXED_HASH_BYTES
            or retention_deadline > UINT64_MAX
        ):
            raise ObservableApprovalOutboxError()
        statement_digest = _validate_outbox_statement(
            statement_wire,
            verified.network_id,
            observable_commitment=verified.observable_commitment,
            report_nonce=report_nonce,
        )
        try:
            bundle = ObservableBundle.parse_canonical(bundle_wire)
            recomputed = bundle.commitment(verified.network_id, report_nonce.hex())
        except ValueError:
            raise ObservableApprovalOutboxError() from None
        if not hmac.compare_digest(recomputed, verified.observable_commitment):
            raise ObservableApprovalOutboxError()
        connection.execute(
            "DELETE FROM approval_outbox WHERE retention_deadline <= ?",
            (consumed_at,),
        )
        connection.execute(
            "DELETE FROM observable_analysis_results WHERE retention_deadline <= ?",
            (consumed_at,),
        )
        pending = connection.execute("SELECT COUNT(*) FROM approval_outbox").fetchone()[
            0
        ]
        if (
            type(pending) is not int or pending >= retention.max_pending_records
        ):  # pylint: disable=C0123
            raise ObservableApprovalOutboxError()
        connection.execute(
            """
            INSERT INTO approval_outbox (
                approval_id, observable_commitment, bundle_wire, statement_wire,
                statement_digest, report_nonce,
                enqueued_at, retention_deadline, lease_token, lease_expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
            """,
            (
                verified.approval_id,
                verified.observable_commitment,
                bundle_wire,
                statement_wire,
                statement_digest,
                report_nonce,
                consumed_at,
                retention_deadline,
            ),
        )
        connection.execute(
            """
            INSERT INTO threat_hint_v2_pairings (
                statement_digest, approval_id, observable_commitment,
                network_id, consumed_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                statement_digest,
                verified.approval_id,
                verified.observable_commitment,
                verified.network_id,
                consumed_at,
            ),
        )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=0.25, isolation_level=None)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA trusted_schema = OFF")
        return connection

    @staticmethod
    def _validate_schema(
        connection: sqlite3.Connection,
        *,
        governed: bool,
        governed_version: int = _SQLITE_SCHEMA_VERSION_GOVERNED,
    ) -> None:
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
        expected_authority = (
            ("singleton", "INTEGER", 0, 1),
            ("authority_epoch", "INTEGER", 1, 0),
            ("governance_policy_sha256", "BLOB", 1, 0),
            ("retention_policy_sha256", "BLOB", 1, 0),
            ("promotion_policy_sha256", "BLOB", 1, 0),
            ("network_id", "TEXT", 1, 0),
            ("approver_xonly_public_key", "BLOB", 1, 0),
            ("recipient_scope", "BLOB", 1, 0),
            ("authority_not_before", "INTEGER", 1, 0),
            ("authority_not_after", "INTEGER", 1, 0),
        )
        expected_outbox_v3 = (
            ("approval_id", "BLOB", 1, 1),
            ("observable_commitment", "BLOB", 1, 0),
            ("bundle_wire", "BLOB", 1, 0),
            ("enqueued_at", "INTEGER", 1, 0),
            ("retention_deadline", "INTEGER", 1, 0),
            ("lease_token", "BLOB", 0, 0),
            ("lease_expires_at", "INTEGER", 0, 0),
        )
        expected_outbox_v4 = (
            ("approval_id", "BLOB", 1, 1),
            ("observable_commitment", "BLOB", 1, 0),
            ("bundle_wire", "BLOB", 1, 0),
            ("statement_wire", "BLOB", 1, 0),
            ("statement_digest", "BLOB", 1, 0),
            ("report_nonce", "BLOB", 1, 0),
            ("enqueued_at", "INTEGER", 1, 0),
            ("retention_deadline", "INTEGER", 1, 0),
            ("lease_token", "BLOB", 0, 0),
            ("lease_expires_at", "INTEGER", 0, 0),
        )
        expected_results = (
            ("approval_id", "BLOB", 1, 1),
            ("result_wire", "BLOB", 1, 0),
            ("result_digest", "BLOB", 1, 0),
            ("input_identity", "BLOB", 1, 0),
            ("completion_token_digest", "BLOB", 1, 0),
            ("completed_at", "INTEGER", 1, 0),
            ("retention_deadline", "INTEGER", 1, 0),
        )
        expected_pairings = (
            ("statement_digest", "BLOB", 1, 1),
            ("approval_id", "BLOB", 1, 0),
            ("observable_commitment", "BLOB", 1, 0),
            ("network_id", "TEXT", 1, 0),
            ("consumed_at", "INTEGER", 1, 0),
        )
        if governed and governed_version not in (
            _SQLITE_SCHEMA_VERSION_GOVERNED_V3,
            _SQLITE_SCHEMA_VERSION_GOVERNED_V4,
            _SQLITE_SCHEMA_VERSION_GOVERNED,
        ):
            raise ObservableApprovalConsumptionError()
        expected_version = (
            governed_version if governed else _SQLITE_SCHEMA_VERSION_LEGACY
        )
        if (  # pylint: disable=too-many-boolean-expressions
            connection.execute("PRAGMA user_version").fetchone()[0] != expected_version
            or _table_shape(connection, "approval_consumptions")
            != expected_consumptions
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
        expected_outbox = (
            expected_outbox_v3
            if governed_version == _SQLITE_SCHEMA_VERSION_GOVERNED_V3
            else expected_outbox_v4
        )
        if governed and (  # pylint: disable=too-many-boolean-expressions
            _table_shape(connection, "authority_state") != expected_authority
            or not _is_strict_table(connection, "authority_state", 10)
            or connection.execute("SELECT COUNT(*) FROM authority_state").fetchone()[0]
            not in (0, 1)
            or _table_shape(connection, "approval_outbox") != expected_outbox
            or not _is_strict_table(
                connection,
                "approval_outbox",
                7 if governed_version == _SQLITE_SCHEMA_VERSION_GOVERNED_V3 else 10,
            )
            or _unique_index_columns(connection, "approval_outbox")
            != {("approval_id",)}
        ):
            raise ObservableApprovalConsumptionError()
        if (
            governed
            and governed_version
            in (
                _SQLITE_SCHEMA_VERSION_GOVERNED_V4,
                _SQLITE_SCHEMA_VERSION_GOVERNED,
            )
            and (
                _table_shape(connection, "observable_analysis_results")
                != expected_results
                or not _is_strict_table(connection, "observable_analysis_results", 7)
                or _unique_index_columns(connection, "observable_analysis_results")
                != {("approval_id",)}
                or _foreign_key_targets(connection, "observable_analysis_results")
                != {("approval_consumptions", "approval_id", "approval_id")}
            )
        ):
            raise ObservableApprovalConsumptionError()
        if (
            governed
            and governed_version == _SQLITE_SCHEMA_VERSION_GOVERNED
            and (
                _table_shape(connection, "threat_hint_v2_pairings") != expected_pairings
                or not _is_strict_table(connection, "threat_hint_v2_pairings", 5)
                or _unique_index_columns(connection, "threat_hint_v2_pairings")
                != {
                    ("statement_digest",),
                    ("approval_id",),
                    ("observable_commitment",),
                }
                or _foreign_key_targets(connection, "threat_hint_v2_pairings")
                != {("approval_consumptions", "approval_id", "approval_id")}
            )
        ):
            raise ObservableApprovalConsumptionError()


class ObservableApprovalConsumptionService:  # pylint: disable=too-few-public-methods
    """Verify and consume locally without triggering any external side effect."""

    def __init__(self, policy_path: Path) -> None:
        self._policy = load_observable_approval_policy(policy_path)
        self._governance: _GovernanceBinding | None = None
        self._ledger = _ObservableApprovalLedger(self._policy.ledger_path)

    @classmethod
    def from_expected_identity(
        cls,
        policy_path: Path,
        *,
        expected_network_id: str,
        expected_approver_xonly_public_key: bytes,
        expected_recipient_scope: bytes,
    ) -> ObservableApprovalConsumptionService:
        """Build only when the owner policy exactly matches the expected identity.

        The policy file is loaded exactly once. The supplied expected values
        are restrictions only: they can reject, never override, the loaded
        policy. Any mismatch fails before the ledger file is created or
        opened, and the service is built from the same loaded snapshot.
        """
        policy = load_observable_approval_policy(policy_path)
        if (
            type(expected_network_id) is not str  # pylint: disable=C0123
            or type(expected_approver_xonly_public_key)
            is not bytes  # pylint: disable=C0123
            or type(expected_recipient_scope) is not bytes  # pylint: disable=C0123
        ):
            raise ObservableApprovalConsumptionError()
        if expected_network_id != policy.network_id:
            raise ObservableApprovalConsumptionError()
        if not hmac.compare_digest(
            expected_approver_xonly_public_key,
            policy.approver_xonly_public_key,
        ):
            raise ObservableApprovalConsumptionError()
        if not hmac.compare_digest(
            expected_recipient_scope,
            policy.recipient_scope,
        ):
            raise ObservableApprovalConsumptionError()
        service = object.__new__(cls)
        service._policy = policy
        service._governance = None
        service._ledger = _ObservableApprovalLedger(policy.ledger_path)
        return service

    @classmethod
    def from_governed_expected_identity(  # pylint: disable=too-many-arguments
        cls,
        policy_path: Path,
        governance_policy_path: Path,
        retention_policy_path: Path,
        *,
        expected_network_id: str,
        expected_approver_xonly_public_key: bytes,
        expected_recipient_scope: bytes,
        expected_allowed_observable_kinds: frozenset[ObservableKind],
        expected_promotion_policy_sha256: bytes,
        durable_outbox: bool = False,
    ) -> ObservableApprovalConsumptionService:
        """Build one cross-policy snapshot before migrating or opening the ledger."""
        if type(durable_outbox) is not bool:  # pylint: disable=C0123
            raise ObservableApprovalConsumptionError()
        _validate_expected_identity(
            expected_network_id,
            expected_approver_xonly_public_key,
            expected_recipient_scope,
        )
        if (
            type(expected_promotion_policy_sha256) is not bytes
            or len(expected_promotion_policy_sha256) != FIXED_HASH_BYTES
        ):
            raise ObservableApprovalConsumptionError()
        policy = load_observable_approval_policy(policy_path)
        _require_expected_policy_identity(
            policy,
            expected_network_id=expected_network_id,
            expected_approver_xonly_public_key=(expected_approver_xonly_public_key),
            expected_recipient_scope=expected_recipient_scope,
        )
        if (
            type(expected_allowed_observable_kinds) is not frozenset
            or not expected_allowed_observable_kinds
            or any(
                type(kind) is not ObservableKind
                for kind in expected_allowed_observable_kinds
            )
        ):
            raise ObservableApprovalConsumptionError()
        try:
            governance_policy = load_threat_hint_v2_governance_policy(
                governance_policy_path,
                expected_network_id=expected_network_id,
                expected_approver_xonly_public_key=(expected_approver_xonly_public_key),
                expected_recipient_scope=expected_recipient_scope,
            )
            retention_policy = load_outbox_retention_policy(
                retention_policy_path,
                expected_network_id=expected_network_id,
                expected_approver_xonly_public_key=(expected_approver_xonly_public_key),
                expected_recipient_scope=expected_recipient_scope,
            )
        except (ThreatHintV2GovernancePolicyError, OutboxRetentionPolicyError):
            raise ObservableApprovalConsumptionError() from None
        if (
            governance_policy.allowed_observable_kinds
            != expected_allowed_observable_kinds
            or retention_policy.durable_observable_kinds
            != expected_allowed_observable_kinds
        ):
            raise ObservableApprovalConsumptionError()
        governance = _GovernanceBinding(
            policy=governance_policy,
            retention=retention_policy,
            promotion_policy_sha256=expected_promotion_policy_sha256,
        )
        service = object.__new__(cls)
        service._policy = policy
        service._governance = governance
        service._ledger = _ObservableApprovalLedger(
            policy.ledger_path,
            governance=governance,
            durable_outbox=durable_outbox,
        )
        return service

    def precheck_governance(
        self,
        approval_wire: bytes,
        bundle_wire: bytes,
        *,
        report_nonce: bytes,
        current_time: int,
    ) -> None:
        """Fail fast before proof verification; consume re-checks everything."""
        governance = self._require_governance()
        verified = self._verify(
            approval_wire,
            bundle_wire,
            report_nonce=report_nonce,
            current_time=current_time,
        )
        self._validate_governance(verified, bundle_wire, current_time, governance)
        self._ledger.assert_authority_snapshot(governance)

    def consume(
        self,
        approval_wire: bytes,
        bundle_wire: bytes,
        *,
        report_nonce: bytes,
        current_time: int,
    ) -> ObservableApprovalConsumptionReceipt:
        """Verify from trusted inputs and durably consume in the same call path."""
        verified = self._verify(
            approval_wire,
            bundle_wire,
            report_nonce=report_nonce,
            current_time=current_time,
        )
        governance = self._governance
        if governance is None:
            return self._ledger.consume(verified, current_time)
        self._validate_governance(verified, bundle_wire, current_time, governance)
        return self._ledger.consume_governed(
            verified,
            current_time,
            governance,
            bundle_wire,
            statement_wire=None,
            report_nonce=report_nonce,
        )

    # pylint: disable-next=too-many-arguments
    def consume_expected(
        self,
        approval_wire: bytes,
        bundle_wire: bytes,
        *,
        report_nonce: bytes,
        current_time: int,
        expected_approval_id: bytes,
        expected_observable_commitment: bytes,
    ) -> ObservableApprovalConsumptionReceipt:
        """Consume only when the verified identity matches the expected values.

        The raw approval and bundle wires are re-verified against the owner
        policy in this same call path. The expected approval identifier and
        observable commitment are restrictions only and are compared before
        the atomic durable consume, so a mismatch can never be discovered
        after a commit.
        """
        return self._consume_expected(
            approval_wire,
            bundle_wire,
            report_nonce=report_nonce,
            current_time=current_time,
            expected_approval_id=expected_approval_id,
            expected_observable_commitment=expected_observable_commitment,
            statement_wire=None,
        )

    # pylint: disable-next=too-many-arguments
    def _consume_expected(
        self,
        approval_wire: bytes,
        bundle_wire: bytes,
        *,
        report_nonce: bytes,
        current_time: int,
        expected_approval_id: bytes,
        expected_observable_commitment: bytes,
        statement_wire: bytes | None,
    ) -> ObservableApprovalConsumptionReceipt:
        """Trusted acceptance-only variant carrying the verified statement."""
        if (
            type(expected_approval_id) is not bytes  # pylint: disable=C0123
            or len(expected_approval_id) != FIXED_HASH_BYTES
            or type(expected_observable_commitment)
            is not bytes  # pylint: disable=C0123
            or len(expected_observable_commitment) != FIXED_HASH_BYTES
        ):
            raise ObservableApprovalConsumptionError()
        verified = self._verify(
            approval_wire,
            bundle_wire,
            report_nonce=report_nonce,
            current_time=current_time,
        )
        if not hmac.compare_digest(
            verified.approval_id, expected_approval_id
        ) or not hmac.compare_digest(
            verified.observable_commitment, expected_observable_commitment
        ):
            raise ObservableApprovalConsumptionError()
        governance = self._governance
        if governance is None:
            return self._ledger.consume(verified, current_time)
        self._validate_governance(verified, bundle_wire, current_time, governance)
        return self._ledger.consume_governed(
            verified,
            current_time,
            governance,
            bundle_wire,
            statement_wire=statement_wire,
            report_nonce=report_nonce,
        )

    def outbox(self) -> ObservableApprovalOutbox:
        """Expose the governed local outbox claim boundary; legacy has none."""
        if self._governance is None:
            raise ObservableApprovalGovernanceUnavailableError()
        return ObservableApprovalOutbox(self._ledger, self._policy.network_id)

    def _verify(
        self,
        approval_wire: bytes,
        bundle_wire: bytes,
        *,
        report_nonce: bytes,
        current_time: int,
    ) -> VerifiedObservableApproval:
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
            return verify_observable_approval(approval_wire, bundle_wire, context)
        except ObservableApprovalError:
            raise ObservableApprovalConsumptionError() from None

    def _require_governance(self) -> _GovernanceBinding:
        governance = self._governance
        if governance is None:
            raise ObservableApprovalGovernanceUnavailableError()
        return governance

    @staticmethod
    def _validate_governance(
        verified: VerifiedObservableApproval,
        bundle_wire: bytes,
        current_time: int,
        governance: _GovernanceBinding,
    ) -> None:
        policy = governance.policy
        if (
            current_time < policy.authority_not_before
            or current_time > policy.authority_not_after
            or verified.not_before < policy.authority_not_before
            or verified.expires_at > policy.authority_not_after
        ):
            raise ObservableApprovalGovernanceCandidateError()
        try:
            bundle = ObservableBundle.parse_canonical(bundle_wire)
        except ValueError:
            raise ObservableApprovalGovernanceCandidateError() from None
        if any(
            observable.kind not in policy.allowed_observable_kinds
            for observable in bundle.observables
        ):
            raise ObservableApprovalGovernanceCandidateError()


class ObservableApprovalOutbox:
    """Single-winner lease boundary over the governed durable outbox.

    The state machine is pending (lease columns null) -> leased -> durable
    result plus terminal outbox deletion. Claim and complete each run in their
    own ``BEGIN IMMEDIATE`` transaction on the same ledger file, so concurrent
    claims and completions serialize on the SQLite write lock. Worker and
    analyzer execution remain outside this durable boundary.
    """

    def __init__(self, ledger: _ObservableApprovalLedger, network_id: str) -> None:
        try:
            validate_network_id(network_id)
        except ValueError:
            raise ObservableApprovalOutboxError() from None
        self._ledger = ledger
        self._network_id = network_id

    def claim(
        self,
        *,
        current_time: int,
        lease_seconds: int,
    ) -> ObservableApprovalOutboxClaim | None:
        """Lease the deterministically oldest eligible record at most once.

        Eligible means not past its retention deadline and either pending or
        holding an expired lease. The lease token is generated internally and
        the lease expiry never extends past the record's retention deadline.
        An empty or fully leased queue returns ``None``.
        """
        if (
            not _is_timestamp(current_time)
            or type(lease_seconds) is not int  # pylint: disable=C0123
            or not 1 <= lease_seconds <= MAX_OUTBOX_LEASE_SECONDS
        ):
            raise ObservableApprovalOutboxError()
        lease_end = current_time + lease_seconds
        if lease_end > UINT64_MAX:
            raise ObservableApprovalOutboxError()
        try:
            with closing(
                self._ledger._connect()  # pylint: disable=protected-access
            ) as connection:
                with connection:
                    connection.execute("BEGIN IMMEDIATE")
                    if (
                        connection.execute("PRAGMA user_version").fetchone()[0]
                        != _SQLITE_SCHEMA_VERSION_GOVERNED
                    ):
                        raise ObservableApprovalOutboxError()
                    connection.execute(
                        "DELETE FROM approval_outbox WHERE retention_deadline <= ?",
                        (current_time,),
                    )
                    connection.execute(
                        "DELETE FROM observable_analysis_results "
                        "WHERE retention_deadline <= ?",
                        (current_time,),
                    )
                    row = connection.execute(
                        """
                        SELECT approval_id, observable_commitment, bundle_wire,
                               statement_wire, statement_digest, report_nonce,
                               retention_deadline
                        FROM approval_outbox
                        WHERE retention_deadline > ?
                          AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
                        ORDER BY enqueued_at ASC, approval_id ASC
                        LIMIT 1
                        """,
                        (current_time, current_time),
                    ).fetchone()
                    if row is None:
                        return None
                    _validate_outbox_row(row)
                    _revalidate_outbox_row(row, self._network_id)
                    lease_token = os.urandom(FIXED_HASH_BYTES)
                    lease_expires_at = min(lease_end, row[6])
                    updated = connection.execute(
                        """
                        UPDATE approval_outbox
                        SET lease_token = ?, lease_expires_at = ?
                        WHERE approval_id = ?
                          AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
                        """,
                        (lease_token, lease_expires_at, row[0], current_time),
                    )
                    if updated.rowcount != 1:
                        raise ObservableApprovalOutboxError()
        except ObservableApprovalConsumptionError:
            raise
        except sqlite3.OperationalError as exc:
            _raise_operational_error(exc)
        except (sqlite3.Error, OSError, OverflowError):
            raise ObservableApprovalOutboxError() from None
        return _build_outbox_claim(
            row,
            lease_token,
            lease_expires_at,
            self._network_id,
        )

    # pylint: disable-next=too-many-arguments,too-many-locals,too-many-statements
    def complete(
        self,
        *,
        approval_id: bytes,
        lease_token: bytes,
        completion_token: bytes,
        input_identity: bytes,
        result_wire: bytes,
        current_time: int,
    ) -> ObservableAnalysisCompletion:
        """Atomically store one exact result and remove its leased outbox row."""
        if (
            not _is_fixed_bytes(approval_id)
            or not _is_fixed_bytes(lease_token)
            or not _is_fixed_bytes(completion_token)
            or not _is_fixed_bytes(input_identity)
            or not _is_timestamp(current_time)
        ):
            raise ObservableApprovalOutboxError()
        _validate_analysis_result_wire(
            result_wire,
            expected_approval_id=approval_id,
            expected_input_identity=input_identity,
        )
        completion_token_digest = _completion_token_digest(
            completion_token, lease_token
        )
        try:
            with closing(
                self._ledger._connect()  # pylint: disable=protected-access
            ) as connection:
                with connection:
                    connection.execute("BEGIN IMMEDIATE")
                    if (
                        connection.execute("PRAGMA user_version").fetchone()[0]
                        != _SQLITE_SCHEMA_VERSION_GOVERNED
                    ):
                        raise ObservableApprovalOutboxError()
                    connection.execute(
                        "DELETE FROM approval_outbox WHERE retention_deadline <= ?",
                        (current_time,),
                    )
                    connection.execute(
                        "DELETE FROM observable_analysis_results "
                        "WHERE retention_deadline <= ?",
                        (current_time,),
                    )
                    row = connection.execute(
                        """
                        SELECT approval_id, observable_commitment, bundle_wire,
                               statement_wire, statement_digest, report_nonce,
                               retention_deadline, lease_token, lease_expires_at
                        FROM approval_outbox
                        WHERE approval_id = ?
                        """,
                        (approval_id,),
                    ).fetchone()
                    if row is None:
                        stored = connection.execute(
                            """
                            SELECT result_wire, result_digest, input_identity,
                                   completion_token_digest, completed_at,
                                   retention_deadline
                            FROM observable_analysis_results
                            WHERE approval_id = ?
                            """,
                            (approval_id,),
                        ).fetchone()
                        stored = _validate_completion_retry_row(
                            stored, approval_id=approval_id
                        )
                        if (
                            not hmac.compare_digest(stored[0], result_wire)
                            or not hmac.compare_digest(stored[2], input_identity)
                            or not hmac.compare_digest(
                                stored[3], completion_token_digest
                            )
                        ):
                            raise ObservableApprovalOutboxError()
                        result_digest = stored[1]
                        completed_at = stored[4]
                        retention_deadline = stored[5]
                    else:
                        if type(row) is not tuple or len(row) != 9:
                            raise ObservableApprovalOutboxError()
                        claim_row = row[:7]
                        _validate_outbox_row(claim_row)
                        _revalidate_outbox_row(claim_row, self._network_id)
                        stored_lease_token = row[7]
                        lease_expires_at = row[8]
                        if (
                            not _is_fixed_bytes(stored_lease_token)
                            or type(lease_expires_at) is not int
                            or lease_expires_at <= current_time
                            or not hmac.compare_digest(stored_lease_token, lease_token)
                        ):
                            raise ObservableApprovalOutboxError()
                        expected_identity = _analysis_input_identity(
                            network_id=self._network_id,
                            statement_wire=row[3],
                            bundle_wire=row[2],
                            approval_id=row[0],
                            observable_commitment=row[1],
                            lease_token=stored_lease_token,
                            lease_expires_at=lease_expires_at,
                            retention_deadline=row[6],
                        )
                        if not hmac.compare_digest(expected_identity, input_identity):
                            raise ObservableApprovalOutboxError()
                        _validate_analysis_result_wire(
                            result_wire,
                            expected_approval_id=approval_id,
                            expected_input_identity=input_identity,
                            expected_statement_digest=row[4],
                            expected_observable_commitment=row[1],
                        )
                        result_digest = _analysis_result_record_digest(
                            result_wire,
                            completed_at=current_time,
                            retention_deadline=row[6],
                        )
                        connection.execute(
                            """
                            INSERT INTO observable_analysis_results (
                                approval_id, result_wire, result_digest,
                                input_identity, completion_token_digest,
                                completed_at, retention_deadline
                            ) VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                approval_id,
                                result_wire,
                                result_digest,
                                input_identity,
                                completion_token_digest,
                                current_time,
                                row[6],
                            ),
                        )
                        deleted = connection.execute(
                            """
                            DELETE FROM approval_outbox
                            WHERE approval_id = ? AND lease_token = ?
                              AND lease_expires_at > ?
                            """,
                            (approval_id, lease_token, current_time),
                        )
                        if deleted.rowcount != 1:
                            raise ObservableApprovalOutboxError()
                        completed_at = current_time
                        retention_deadline = row[6]
        except ObservableApprovalConsumptionError:
            raise
        except sqlite3.OperationalError as exc:
            _raise_operational_error(exc)
        except (sqlite3.Error, OSError, OverflowError):
            raise ObservableApprovalOutboxError() from None
        return _build_analysis_completion(
            approval_id,
            result_digest,
            input_identity,
            completed_at,
            retention_deadline,
        )

    def result(
        self,
        *,
        approval_id: bytes,
        current_time: int,
    ) -> ObservableAnalysisStoredResult | None:
        """Recover one unexpired owner-local result and revalidate its wire."""
        if not _is_fixed_bytes(approval_id) or not _is_timestamp(current_time):
            raise ObservableApprovalOutboxError()
        try:
            with closing(
                self._ledger._connect()  # pylint: disable=protected-access
            ) as connection:
                with connection:
                    connection.execute("BEGIN IMMEDIATE")
                    if (
                        connection.execute("PRAGMA user_version").fetchone()[0]
                        != _SQLITE_SCHEMA_VERSION_GOVERNED
                    ):
                        raise ObservableApprovalOutboxError()
                    connection.execute(
                        "DELETE FROM observable_analysis_results "
                        "WHERE retention_deadline <= ?",
                        (current_time,),
                    )
                    row = connection.execute(
                        """
                        SELECT approval_id, result_wire, result_digest,
                               input_identity, completed_at, retention_deadline
                        FROM observable_analysis_results
                        WHERE approval_id = ?
                        """,
                        (approval_id,),
                    ).fetchone()
                    if row is None:
                        return None
                    _validate_stored_result_row(row)
                    _validate_analysis_result_wire(
                        row[1],
                        expected_approval_id=row[0],
                        expected_input_identity=row[3],
                    )
                    recomputed = _analysis_result_record_digest(
                        row[1],
                        completed_at=row[4],
                        retention_deadline=row[5],
                    )
                    if not hmac.compare_digest(recomputed, row[2]):
                        raise ObservableApprovalOutboxError()
        except ObservableApprovalConsumptionError:
            raise
        except sqlite3.OperationalError as exc:
            _raise_operational_error(exc)
        except (sqlite3.Error, OverflowError):
            raise ObservableApprovalOutboxError() from None
        return _build_stored_result(row)

    def acknowledge(self, *, approval_id: bytes, lease_token: bytes) -> None:
        """Reject deletion without a durable v4 analysis result."""
        if (
            type(approval_id) is not bytes  # pylint: disable=C0123
            or len(approval_id) != FIXED_HASH_BYTES
            or type(lease_token) is not bytes  # pylint: disable=C0123
            or len(lease_token) != FIXED_HASH_BYTES
        ):
            raise ObservableApprovalOutboxError()
        raise ObservableApprovalOutboxError()


def _validate_outbox_row(row: tuple) -> None:
    if (  # pylint: disable=too-many-boolean-expressions
        type(row) is not tuple  # pylint: disable=C0123
        or len(row) != 7
        or type(row[0]) is not bytes  # pylint: disable=C0123
        or len(row[0]) != FIXED_HASH_BYTES
        or type(row[1]) is not bytes  # pylint: disable=C0123
        or len(row[1]) != FIXED_HASH_BYTES
        or type(row[2]) is not bytes  # pylint: disable=C0123
        or not 1 <= len(row[2]) <= MAX_CANONICAL_BYTES
        or type(row[3]) is not bytes  # pylint: disable=C0123
        or not 1 <= len(row[3]) <= MAX_CANONICAL_V2_STATEMENT_BYTES
        or type(row[4]) is not bytes  # pylint: disable=C0123
        or len(row[4]) != FIXED_HASH_BYTES
        or type(row[5]) is not bytes  # pylint: disable=C0123
        or len(row[5]) != FIXED_HASH_BYTES
        or type(row[6]) is not int  # pylint: disable=C0123
        or row[6] < 1
    ):
        raise ObservableApprovalOutboxError()


def _validate_outbox_statement(
    statement_wire: bytes,
    network_id: str,
    *,
    observable_commitment: bytes,
    report_nonce: bytes,
) -> bytes:
    if (
        type(statement_wire) is not bytes  # pylint: disable=C0123
        or not 1 <= len(statement_wire) <= MAX_CANONICAL_V2_STATEMENT_BYTES
        or not _is_fixed_bytes(observable_commitment)
        or not _is_fixed_bytes(report_nonce)
    ):
        raise ObservableApprovalOutboxError()
    try:
        statement = ThreatHintV2Statement.parse_canonical(statement_wire, network_id)
        statement_digest = statement.statement_digest()
    except (ThreatHintV2StatementError, ValueError):
        raise ObservableApprovalOutboxError() from None
    if (
        statement.observable_commitment != observable_commitment.hex()
        or statement.report_nonce != report_nonce.hex()
    ):
        raise ObservableApprovalOutboxError()
    return statement_digest


def _revalidate_outbox_row(row: tuple, network_id: str) -> None:
    _validate_outbox_row(row)
    statement_digest = _validate_outbox_statement(
        row[3],
        network_id,
        observable_commitment=row[1],
        report_nonce=row[5],
    )
    if not hmac.compare_digest(statement_digest, row[4]):
        raise ObservableApprovalOutboxError()
    try:
        bundle = ObservableBundle.parse_canonical(row[2])
        recomputed = bundle.commitment(network_id, row[5].hex())
    except ValueError:
        raise ObservableApprovalOutboxError() from None
    if not hmac.compare_digest(recomputed, row[1]):
        raise ObservableApprovalOutboxError()


def _build_outbox_claim(
    row: tuple,
    lease_token: bytes,
    lease_expires_at: int,
    network_id: str,
) -> ObservableApprovalOutboxClaim:
    claim = object.__new__(ObservableApprovalOutboxClaim)
    object.__setattr__(claim, "approval_id", row[0])
    object.__setattr__(claim, "observable_commitment", row[1])
    object.__setattr__(claim, "bundle_wire", row[2])
    object.__setattr__(claim, "statement_wire", row[3])
    object.__setattr__(claim, "statement_digest", row[4])
    object.__setattr__(claim, "report_nonce", row[5])
    object.__setattr__(claim, "lease_token", lease_token)
    object.__setattr__(claim, "lease_expires_at", lease_expires_at)
    object.__setattr__(
        claim,
        "input_identity",
        _analysis_input_identity(
            network_id=network_id,
            statement_wire=row[3],
            bundle_wire=row[2],
            approval_id=row[0],
            observable_commitment=row[1],
            lease_token=lease_token,
            lease_expires_at=lease_expires_at,
            retention_deadline=row[6],
        ),
    )
    return claim


def _analysis_input_identity(  # pylint: disable=too-many-arguments
    *,
    network_id: str,
    statement_wire: bytes,
    bundle_wire: bytes,
    approval_id: bytes,
    observable_commitment: bytes,
    lease_token: bytes,
    lease_expires_at: int,
    retention_deadline: int,
) -> bytes:
    try:
        validate_network_id(network_id)
        network_wire = network_id.encode("ascii")
    except (UnicodeError, ValueError):
        raise ObservableApprovalOutboxError() from None
    if (
        not _is_fixed_bytes(approval_id)
        or not _is_fixed_bytes(observable_commitment)
        or not _is_fixed_bytes(lease_token)
        or type(statement_wire) is not bytes  # pylint: disable=C0123
        or not 1 <= len(statement_wire) <= MAX_CANONICAL_V2_STATEMENT_BYTES
        or type(bundle_wire) is not bytes  # pylint: disable=C0123
        or not 1 <= len(bundle_wire) <= MAX_CANONICAL_BYTES
        or not _is_timestamp(lease_expires_at)
        or not _is_timestamp(retention_deadline)
        or lease_expires_at > retention_deadline
    ):
        raise ObservableApprovalOutboxError()
    digest = hashlib.sha256()
    digest.update(ANALYSIS_INPUT_IDENTITY_DOMAIN)
    digest.update(len(network_wire).to_bytes(2, byteorder="big", signed=False))
    digest.update(network_wire)
    for wire in (statement_wire, bundle_wire):
        digest.update(len(wire).to_bytes(4, byteorder="big", signed=False))
        digest.update(wire)
    digest.update(approval_id)
    digest.update(observable_commitment)
    digest.update(lease_token)
    digest.update(lease_expires_at.to_bytes(8, byteorder="big", signed=False))
    digest.update(retention_deadline.to_bytes(8, byteorder="big", signed=False))
    return digest.digest()


def build_analysis_result_wire(  # pylint: disable=too-many-arguments
    *,
    analyzer_id: str,
    approval_id: bytes,
    input_identity: bytes,
    statement_digest: bytes,
    observable_commitment: bytes,
    observable_count: int,
) -> bytes:
    """Build one exact canonical result with no actionable output surface."""
    if (
        not _is_analyzer_id(analyzer_id)
        or not _is_fixed_bytes(approval_id)
        or not _is_fixed_bytes(input_identity)
        or not _is_fixed_bytes(statement_digest)
        or not _is_fixed_bytes(observable_commitment)
        or type(observable_count) is not int  # pylint: disable=C0123
        or not 1 <= observable_count <= MAX_OBSERVABLES
    ):
        raise ObservableApprovalOutboxError()
    wire = json.dumps(
        {
            "schema_version": ANALYSIS_RESULT_SCHEMA_VERSION,
            "result_kind": ANALYSIS_RESULT_KIND,
            "analyzer_id": analyzer_id,
            "approval_id": approval_id.hex(),
            "input_identity": input_identity.hex(),
            "statement_digest": statement_digest.hex(),
            "observable_commitment": observable_commitment.hex(),
            "observable_count": observable_count,
        },
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    if not 1 <= len(wire) <= MAX_CANONICAL_ANALYSIS_RESULT_BYTES:
        raise ObservableApprovalOutboxError()
    return wire


def _validate_analysis_result_wire(
    result_wire: bytes,
    *,
    expected_approval_id: bytes,
    expected_input_identity: bytes,
    expected_statement_digest: bytes | None = None,
    expected_observable_commitment: bytes | None = None,
) -> None:
    if (
        type(result_wire) is not bytes  # pylint: disable=C0123
        or not 1 <= len(result_wire) <= MAX_CANONICAL_ANALYSIS_RESULT_BYTES
        or not _is_fixed_bytes(expected_approval_id)
        or not _is_fixed_bytes(expected_input_identity)
        or (
            expected_statement_digest is not None
            and not _is_fixed_bytes(expected_statement_digest)
        )
        or (
            expected_observable_commitment is not None
            and not _is_fixed_bytes(expected_observable_commitment)
        )
    ):
        raise ObservableApprovalOutboxError()
    try:
        decoded = json.loads(
            result_wire.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_analysis_keys,
        )
    except (UnicodeError, ValueError, RecursionError):
        raise ObservableApprovalOutboxError() from None
    if (
        type(decoded) is not dict
        or tuple(decoded) != _ANALYSIS_RESULT_FIELDS
        or type(decoded["schema_version"]) is not int  # pylint: disable=C0123
        or decoded["schema_version"] != ANALYSIS_RESULT_SCHEMA_VERSION
        or type(decoded["result_kind"]) is not str  # pylint: disable=C0123
        or decoded["result_kind"] != ANALYSIS_RESULT_KIND
        or not _is_analyzer_id(decoded["analyzer_id"])
        or not _is_fixed_lower_hex(decoded["approval_id"])
        or not _is_fixed_lower_hex(decoded["input_identity"])
        or not _is_fixed_lower_hex(decoded["statement_digest"])
        or not _is_fixed_lower_hex(decoded["observable_commitment"])
        or type(decoded["observable_count"]) is not int  # pylint: disable=C0123
        or not 1 <= decoded["observable_count"] <= MAX_OBSERVABLES
    ):
        raise ObservableApprovalOutboxError()
    canonical = json.dumps(decoded, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    if (
        canonical != result_wire
        or decoded["approval_id"] != expected_approval_id.hex()
        or decoded["input_identity"] != expected_input_identity.hex()
        or (
            expected_statement_digest is not None
            and decoded["statement_digest"] != expected_statement_digest.hex()
        )
        or (
            expected_observable_commitment is not None
            and decoded["observable_commitment"] != expected_observable_commitment.hex()
        )
    ):
        raise ObservableApprovalOutboxError()


def _analysis_result_record_digest(
    result_wire: bytes,
    *,
    completed_at: int,
    retention_deadline: int,
) -> bytes:
    if (
        type(result_wire) is not bytes  # pylint: disable=C0123
        or not 1 <= len(result_wire) <= MAX_CANONICAL_ANALYSIS_RESULT_BYTES
        or not _is_timestamp(completed_at)
        or not _is_timestamp(retention_deadline)
        or retention_deadline < completed_at
    ):
        raise ObservableApprovalOutboxError()
    digest = hashlib.sha256()
    digest.update(ANALYSIS_RESULT_DIGEST_DOMAIN)
    digest.update(len(result_wire).to_bytes(4, byteorder="big", signed=False))
    digest.update(result_wire)
    digest.update(completed_at.to_bytes(8, byteorder="big", signed=False))
    digest.update(retention_deadline.to_bytes(8, byteorder="big", signed=False))
    return digest.digest()


def _completion_token_digest(completion_token: bytes, lease_token: bytes) -> bytes:
    if not _is_fixed_bytes(completion_token) or not _is_fixed_bytes(lease_token):
        raise ObservableApprovalOutboxError()
    digest = hashlib.sha256()
    digest.update(COMPLETION_TOKEN_DIGEST_DOMAIN)
    digest.update(completion_token)
    digest.update(lease_token)
    return digest.digest()


def _validate_completion_retry_row(
    row: tuple | None,
    *,
    approval_id: bytes,
) -> tuple:
    if (
        type(row) is not tuple  # pylint: disable=C0123
        or len(row) != 6
        or type(row[0]) is not bytes  # pylint: disable=C0123
        or not 1 <= len(row[0]) <= MAX_CANONICAL_ANALYSIS_RESULT_BYTES
        or not _is_fixed_bytes(row[1])
        or not _is_fixed_bytes(row[2])
        or not _is_fixed_bytes(row[3])
        or not _is_timestamp(row[4])
        or not _is_timestamp(row[5])
        or row[5] < row[4]
    ):
        raise ObservableApprovalOutboxError()
    _validate_analysis_result_wire(
        row[0],
        expected_approval_id=approval_id,
        expected_input_identity=row[2],
    )
    recomputed = _analysis_result_record_digest(
        row[0],
        completed_at=row[4],
        retention_deadline=row[5],
    )
    if not hmac.compare_digest(recomputed, row[1]):
        raise ObservableApprovalOutboxError()
    return row


def _validate_stored_result_row(row: tuple) -> None:
    if (
        type(row) is not tuple  # pylint: disable=C0123
        or len(row) != 6
        or not _is_fixed_bytes(row[0])
        or type(row[1]) is not bytes  # pylint: disable=C0123
        or not 1 <= len(row[1]) <= MAX_CANONICAL_ANALYSIS_RESULT_BYTES
        or not _is_fixed_bytes(row[2])
        or not _is_fixed_bytes(row[3])
        or not _is_timestamp(row[4])
        or not _is_timestamp(row[5])
        or row[5] < row[4]
    ):
        raise ObservableApprovalOutboxError()


def _build_analysis_completion(
    approval_id: bytes,
    result_digest: bytes,
    input_identity: bytes,
    completed_at: int,
    retention_deadline: int,
) -> ObservableAnalysisCompletion:
    completion = object.__new__(ObservableAnalysisCompletion)
    object.__setattr__(completion, "approval_id", approval_id)
    object.__setattr__(completion, "result_digest", result_digest)
    object.__setattr__(completion, "input_identity", input_identity)
    object.__setattr__(completion, "completed_at", completed_at)
    object.__setattr__(completion, "retention_deadline", retention_deadline)
    return completion


def _build_stored_result(row: tuple) -> ObservableAnalysisStoredResult:
    result = object.__new__(ObservableAnalysisStoredResult)
    object.__setattr__(result, "approval_id", row[0])
    object.__setattr__(result, "result_wire", row[1])
    object.__setattr__(result, "result_digest", row[2])
    object.__setattr__(result, "input_identity", row[3])
    object.__setattr__(result, "completed_at", row[4])
    object.__setattr__(result, "retention_deadline", row[5])
    return result


def _reject_duplicate_analysis_keys(items: list[tuple[str, object]]) -> dict:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            raise ObservableApprovalOutboxError()
        result[key] = value
    return result


def _is_fixed_bytes(value: object) -> bool:
    return type(value) is bytes and len(value) == FIXED_HASH_BYTES


def _is_fixed_lower_hex(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == FIXED_HASH_BYTES * 2
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_analyzer_id(value: object) -> bool:
    return type(value) is str and _ANALYZER_ID_RE.fullmatch(value) is not None


def _require_expected_policy_identity(
    policy: ObservableApprovalPolicy,
    *,
    expected_network_id: object,
    expected_approver_xonly_public_key: object,
    expected_recipient_scope: object,
) -> None:
    _validate_expected_identity(
        expected_network_id,
        expected_approver_xonly_public_key,
        expected_recipient_scope,
    )
    if (
        expected_network_id != policy.network_id
        or not hmac.compare_digest(
            expected_approver_xonly_public_key,
            policy.approver_xonly_public_key,
        )
        or not hmac.compare_digest(
            expected_recipient_scope,
            policy.recipient_scope,
        )
    ):
        raise ObservableApprovalConsumptionError()


def _validate_expected_identity(
    expected_network_id: object,
    expected_approver_xonly_public_key: object,
    expected_recipient_scope: object,
) -> None:
    if (
        type(expected_network_id) is not str
        or type(expected_approver_xonly_public_key) is not bytes
        or len(expected_approver_xonly_public_key) != FIXED_HASH_BYTES
        or type(expected_recipient_scope) is not bytes
        or len(expected_recipient_scope) != FIXED_HASH_BYTES
    ):
        raise ObservableApprovalConsumptionError()
    try:
        validate_network_id(expected_network_id)
    except ValueError:
        raise ObservableApprovalConsumptionError() from None


def _read_owner_policy_file(path: Path) -> bytes:
    if os.name != "posix" or not hasattr(os, "getuid") or not hasattr(os, "O_NOFOLLOW"):
        raise ObservableApprovalConsumptionError()
    if (
        not isinstance(path, Path)
        or type(path) not in (Path, PosixPath, WindowsPath)
        or not path.is_absolute()
        or path.name in {"", ".", ".."}
        or ".." in path.parts
    ):
        raise ObservableApprovalConsumptionError()
    try:
        parent = path.parent.resolve(strict=True)
        parent_stat = parent.stat()
        before = path.lstat()
        candidate = parent / path.name
        if (
            candidate != path
            or not _is_safe_policy_parent(parent_stat)
            or not _is_safe_policy_file(before)
        ):
            raise ObservableApprovalConsumptionError()
        descriptor = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(descriptor)
            if (
                before.st_dev != opened.st_dev
                or before.st_ino != opened.st_ino
                or before.st_size != opened.st_size
                or not _is_safe_policy_file(opened)
            ):
                raise ObservableApprovalConsumptionError()
            contents = _read_policy_descriptor(descriptor)
        finally:
            os.close(descriptor)
    except (OSError, ValueError):
        raise ObservableApprovalConsumptionError() from None
    if len(contents) != before.st_size:
        raise ObservableApprovalConsumptionError()
    return contents


def _read_policy_descriptor(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    remaining = MAX_CONSUMPTION_POLICY_BYTES + 1
    while remaining:
        chunk = os.read(descriptor, min(remaining, 64 * 1_024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    contents = b"".join(chunks)
    if len(contents) > MAX_CONSUMPTION_POLICY_BYTES:
        raise ObservableApprovalConsumptionError()
    return contents


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


def _foreign_key_targets(
    connection: sqlite3.Connection, table: str
) -> set[tuple[str, str, str]]:
    return {
        (str(row[2]), str(row[3]), str(row[4]))
        for row in connection.execute(f"PRAGMA foreign_key_list({table})").fetchall()
    }


def _raise_operational_error(error: sqlite3.OperationalError) -> NoReturn:
    error_code = getattr(error, "sqlite_errorcode", None)
    if type(error_code) is int and error_code & 0xFF in {
        sqlite3.SQLITE_BUSY,
        sqlite3.SQLITE_LOCKED,
    }:
        raise ObservableApprovalBusyError() from None
    raise ObservableApprovalConsumptionError() from None
