"""Integration tests for the governed ThreatHint-v2 recoverable outbox."""

# Tests intentionally inspect the local ledger and reuse candidate fixtures.
# pylint: disable=missing-function-docstring,too-many-locals,too-many-lines

from __future__ import annotations

import dataclasses
import hashlib
import os
import pickle
import sqlite3
import threading
import time
from pathlib import Path

import jaeger.observable_approval_consumption as consumption_module
import pytest
from coincurve import PrivateKey, PublicKeyXOnly
from jaeger.observable_approval import UINT64_MAX
from jaeger.observable_approval_consumption import (
    MAX_OUTBOX_LEASE_SECONDS,
    ObservableApprovalBusyError,
    ObservableApprovalConsumptionService,
    ObservableApprovalGovernanceUnavailableError,
    ObservableApprovalOutboxClaim,
    ObservableApprovalOutboxError,
)
from jaeger.threat_hint_v2_acceptance import ThreatHintV2AcceptanceService
from jaeger.threat_hint_v2_promotion import (
    ThreatHintV2PromotionError,
    ThreatHintV2PromotionReplayError,
    ThreatHintV2PromotionService,
    ThreatHintV2PromotionUnavailableError,
)
from jaeger.threat_hint_v2_statement import ThreatHintV2Statement
from jaeger.threat_observable import ObservableKind
from tests.test_threat_hint_v2_acceptance import (
    _accept,
    _consumption_count,
    _high_water,
    _ledger_path,
    _write_consumption_policy,
)
from tests.test_threat_hint_v2_governed_promotion import (
    _ALL_KINDS,
    _authority_state,
    _governed_service,
    _schema_version,
    _write_governance_policy,
    _write_retention_policy,
)
from tests.test_threat_hint_v2_preflight import _Scenario, _signed_approval
from tests.test_threat_hint_v2_preflight import _write_policy as _write_preflight_policy
from tests.test_threat_hint_v2_promotion import _promote
from tests.test_threat_hint_v2_promotion import _service as _legacy_promotion_service
from tests.test_threat_hint_v2_promotion import _write_promotion_policy
from tests.test_threat_hint_v2_verified_preflight import (
    _write_config,
    _write_owner_file,
    _write_verifier,
)

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="governed outbox requires POSIX controls"
)

_V2_CONSUMPTIONS_DDL = """
    CREATE TABLE approval_consumptions (
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
    """
_V2_LEDGER_STATE_DDL = """
    CREATE TABLE ledger_state (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        high_water_seconds INTEGER NOT NULL
    ) STRICT
    """
_V2_AUTHORITY_DDL = """
    CREATE TABLE authority_state (
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
    """
_V3_OUTBOX_DDL = """
    CREATE TABLE approval_outbox (
        approval_id BLOB PRIMARY KEY
            CHECK(length(approval_id) = 32),
        observable_commitment BLOB NOT NULL
            CHECK(length(observable_commitment) = 32),
        bundle_wire BLOB NOT NULL
            CHECK(length(bundle_wire) >= 1),
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
    """


def _outbox_rows(ledger_path: Path) -> list[tuple]:
    with sqlite3.connect(ledger_path) as connection:
        return connection.execute("""
            SELECT approval_id, observable_commitment, bundle_wire,
                   enqueued_at, retention_deadline, lease_token, lease_expires_at
            FROM approval_outbox
            ORDER BY enqueued_at ASC, approval_id ASC
            """).fetchall()


def _outbox_binding_rows(ledger_path: Path) -> list[tuple]:
    with sqlite3.connect(ledger_path) as connection:
        return connection.execute("""
            SELECT statement_wire, statement_digest, report_nonce
            FROM approval_outbox
            ORDER BY enqueued_at ASC, approval_id ASC
            """).fetchall()


def _result_rows(ledger_path: Path) -> list[tuple]:
    with sqlite3.connect(ledger_path) as connection:
        return connection.execute("""
            SELECT approval_id, result_wire, result_digest, input_identity,
                   completion_token_digest, completed_at, retention_deadline
            FROM observable_analysis_results
            ORDER BY approval_id ASC
            """).fetchall()


def _table_names(ledger_path: Path) -> set[str]:
    with sqlite3.connect(ledger_path) as connection:
        return {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }


def _claim_service(
    scenario: _Scenario,
    *,
    key_hex: str | None = None,
) -> ObservableApprovalConsumptionService:
    directory = scenario.directory
    vector = scenario.vector
    return ObservableApprovalConsumptionService.from_governed_expected_identity(
        directory / "consumption-policy.toml",
        directory / "governance-policy.toml",
        directory / "retention-policy.toml",
        expected_network_id=vector["network_id"],
        expected_approver_xonly_public_key=bytes.fromhex(
            key_hex or vector["trusted_approver_xonly_public_key_hex"]
        ),
        expected_recipient_scope=bytes.fromhex(vector["trusted_recipient_scope_hex"]),
        expected_allowed_observable_kinds=frozenset(
            ObservableKind(kind) for kind in _ALL_KINDS
        ),
        expected_promotion_policy_sha256=hashlib.sha256(
            (directory / "promotion-policy.toml").read_bytes()
        ).digest(),
    )


def _rotate_to_new_key(
    scenario: _Scenario,
    key: PrivateKey,
    *,
    epoch: int = 2,
    **service_changes: object,
) -> ThreatHintV2PromotionService:
    key_hex = PublicKeyXOnly.from_secret(key.secret).format().hex()
    _write_preflight_policy(
        scenario.directory,
        scenario.vector,
        scenario.anchor_hex,
        key_hex=key_hex,
    )
    scenario.approval_wire = _signed_approval(scenario, key)
    return _governed_service(scenario, epoch=epoch, key_hex=key_hex, **service_changes)


def _create_v2_ledger(scenario: _Scenario) -> Path:
    ledger = _ledger_path(scenario)
    vector = scenario.vector
    with sqlite3.connect(ledger) as connection:
        connection.execute(_V2_CONSUMPTIONS_DDL)
        connection.execute(_V2_LEDGER_STATE_DDL)
        connection.execute(
            "INSERT INTO ledger_state (singleton, high_water_seconds) VALUES (1, ?)",
            (scenario.current_time,),
        )
        connection.execute(_V2_AUTHORITY_DDL)
        connection.execute(
            """
            INSERT INTO approval_consumptions (
                approval_id, approver_xonly_public_key, approval_nonce,
                observable_commitment, recipient_scope, network_id,
                not_before, expires_at, consumed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                bytes.fromhex(vector["approval_id_hex"]),
                bytes.fromhex(vector["trusted_approver_xonly_public_key_hex"]),
                bytes.fromhex(vector["approval_nonce_hex"]),
                bytes.fromhex(vector["observable_commitment_hex"]),
                bytes.fromhex(vector["trusted_recipient_scope_hex"]),
                vector["network_id"],
                vector["not_before"],
                vector["expires_at"],
                scenario.current_time,
            ),
        )
        connection.execute("PRAGMA user_version = 2")
    ledger.chmod(0o600)
    return ledger


def _create_v3_ledger(scenario: _Scenario, *, pending: bool) -> Path:
    ledger = _create_v2_ledger(scenario)
    with sqlite3.connect(ledger) as connection:
        connection.execute(_V3_OUTBOX_DDL)
        if pending:
            connection.execute(
                """
                INSERT INTO approval_outbox (
                    approval_id, observable_commitment, bundle_wire,
                    enqueued_at, retention_deadline, lease_token, lease_expires_at
                ) VALUES (?, ?, ?, ?, ?, NULL, NULL)
                """,
                (
                    bytes.fromhex(scenario.vector["approval_id_hex"]),
                    bytes.fromhex(scenario.vector["observable_commitment_hex"]),
                    scenario.bundle_wire,
                    scenario.current_time,
                    scenario.current_time + 86400,
                ),
            )
        connection.execute("PRAGMA user_version = 3")
    return ledger


def test_governed_promotion_enqueues_full_bundle_in_one_atomic_commit(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    service = _governed_service(scenario)
    ledger = _ledger_path(scenario)
    assert _schema_version(ledger) == 4
    assert "approval_outbox" in _table_names(ledger)
    assert _outbox_rows(ledger) == []

    result = _promote(service, scenario)

    rows = _outbox_rows(ledger)
    assert len(rows) == 1
    (
        approval_id,
        commitment,
        bundle_wire,
        enqueued_at,
        deadline,
        lease_token,
        lease_expires_at,
    ) = rows[0]
    assert approval_id == result.approval_id
    assert approval_id.hex() == scenario.vector["approval_id_hex"]
    assert commitment.hex() == scenario.vector["observable_commitment_hex"]
    assert bundle_wire == scenario.bundle_wire
    assert enqueued_at == scenario.current_time
    assert deadline == scenario.current_time + 86400
    assert lease_token is None
    assert lease_expires_at is None
    statement = ThreatHintV2Statement.parse_canonical(
        scenario.statement_wire, scenario.vector["network_id"]
    )
    assert _outbox_binding_rows(ledger) == [
        (
            scenario.statement_wire,
            statement.statement_digest(),
            scenario.report_nonce,
        )
    ]
    assert _consumption_count(ledger) == 1
    assert _high_water(ledger) == scenario.current_time
    authority = _authority_state(ledger)
    assert authority is not None
    assert authority[0] == 1


def test_legacy_consumption_stays_v1_without_outbox(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    service = ObservableApprovalConsumptionService(
        _write_consumption_policy(scenario.directory, scenario.vector)
    )
    service.consume(
        scenario.approval_wire,
        scenario.bundle_wire,
        report_nonce=scenario.report_nonce,
        current_time=scenario.current_time,
    )
    ledger = _ledger_path(scenario)
    assert _schema_version(ledger) == 1
    assert "approval_outbox" not in _table_names(ledger)
    with pytest.raises(ObservableApprovalGovernanceUnavailableError):
        service.outbox()


def test_non_governed_promotion_creates_no_outbox(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    _promote(_legacy_promotion_service(scenario), scenario)
    ledger = _ledger_path(scenario)
    assert _schema_version(ledger) == 1
    assert "approval_outbox" not in _table_names(ledger)
    assert _consumption_count(ledger) == 1


def test_governed_acceptance_without_promotion_creates_no_outbox(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    manifest = _write_owner_file(
        scenario.directory / "relation-manifest-v2.json", scenario.manifest_wire
    )
    verifier = _write_verifier(scenario.directory, "/bin/cat >/dev/null\nexit 0")
    config = _write_config(scenario.directory, verifier, manifest)
    consumption = _write_consumption_policy(scenario.directory, scenario.vector)
    promotion = _write_promotion_policy(scenario.directory)
    governance = _write_governance_policy(scenario)
    retention = _write_retention_policy(scenario)
    service = ThreatHintV2AcceptanceService.from_governed_policies(
        config,
        scenario.policy_path,
        consumption,
        governance,
        retention,
        expected_allowed_observable_kinds=frozenset(
            ObservableKind(kind) for kind in _ALL_KINDS
        ),
        expected_promotion_policy_sha256=hashlib.sha256(
            promotion.read_bytes()
        ).digest(),
    )

    _accept(service, scenario)

    ledger = _ledger_path(scenario)
    assert _schema_version(ledger) == 4
    assert "approval_outbox" in _table_names(ledger)
    assert _outbox_rows(ledger) == []
    assert _consumption_count(ledger) == 1


def test_full_outbox_rolls_back_all_states_and_approval_stays_usable(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    _promote(_governed_service(scenario, retention_max_pending_records=1), scenario)
    ledger = _ledger_path(scenario)
    assert len(_outbox_rows(ledger)) == 1

    service = _rotate_to_new_key(
        scenario, PrivateKey(), retention_max_pending_records=1
    )
    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        _promote(service, scenario)
    authority = _authority_state(ledger)
    assert authority is not None
    assert authority[0] == 1
    assert _high_water(ledger) == scenario.current_time
    assert _consumption_count(ledger) == 1
    rows = _outbox_rows(ledger)
    assert len(rows) == 1
    assert rows[0][0].hex() == scenario.vector["approval_id_hex"]

    with sqlite3.connect(ledger) as connection:
        connection.execute("DELETE FROM approval_outbox")
    _promote(service, scenario)
    rows = _outbox_rows(ledger)
    assert len(rows) == 1
    assert rows[0][0].hex() != scenario.vector["approval_id_hex"]
    authority = _authority_state(ledger)
    assert authority is not None
    assert authority[0] == 2
    assert _consumption_count(ledger) == 2


def test_failed_outbox_insert_rolls_back_and_is_not_replay(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    service = _governed_service(scenario)
    ledger = _ledger_path(scenario)
    with sqlite3.connect(ledger) as connection:
        connection.execute("""
            CREATE TRIGGER reject_outbox_enqueue
            BEFORE INSERT ON approval_outbox
            BEGIN
                SELECT RAISE(ABORT, 'injected failure');
            END
            """)

    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        _promote(service, scenario)
    assert _authority_state(ledger) is None
    assert _high_water(ledger) == 0
    assert _consumption_count(ledger) == 0
    assert _outbox_rows(ledger) == []

    with sqlite3.connect(ledger) as connection:
        connection.execute("DROP TRIGGER reject_outbox_enqueue")
    _promote(service, scenario)
    assert len(_outbox_rows(ledger)) == 1
    assert _consumption_count(ledger) == 1


def test_replay_creates_exactly_one_outbox_record(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    service = _governed_service(scenario)
    _promote(service, scenario)
    ledger = _ledger_path(scenario)

    with pytest.raises(ThreatHintV2PromotionReplayError):
        _promote(service, scenario)
    with pytest.raises(ThreatHintV2PromotionReplayError):
        _promote(_governed_service(scenario), scenario)
    assert len(_outbox_rows(ledger)) == 1
    assert _consumption_count(ledger) == 1


def test_restart_leaves_record_claimable(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    _promote(_governed_service(scenario), scenario)

    claim = (
        _claim_service(scenario)
        .outbox()
        .claim(current_time=scenario.current_time, lease_seconds=60)
    )

    assert claim is not None
    assert claim.approval_id.hex() == scenario.vector["approval_id_hex"]
    assert (
        claim.observable_commitment.hex()
        == scenario.vector["observable_commitment_hex"]
    )
    assert claim.bundle_wire == scenario.bundle_wire
    assert claim.statement_wire == scenario.statement_wire
    assert claim.report_nonce == scenario.report_nonce
    assert len(claim.statement_digest) == 32
    assert len(claim.input_identity) == 32
    assert len(claim.lease_token) == 32
    assert claim.lease_expires_at == scenario.current_time + 60
    rows = _outbox_rows(_ledger_path(scenario))
    assert rows[0][5] == claim.lease_token
    assert rows[0][6] == scenario.current_time + 60


def test_concurrent_claim_has_exactly_one_winner(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    _promote(_governed_service(scenario), scenario)
    service = _claim_service(scenario)

    def attempt() -> object:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                return service.outbox().claim(
                    current_time=scenario.current_time, lease_seconds=60
                )
            except ObservableApprovalBusyError:
                time.sleep(0.02)
        raise AssertionError("claim stayed busy")

    results: list[object] = []
    workers = [
        threading.Thread(target=lambda: results.append(attempt())) for _ in range(2)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=30)

    assert all(not worker.is_alive() for worker in workers)
    claims = [result for result in results if result is not None]
    assert len(claims) == 1
    rows = _outbox_rows(_ledger_path(scenario))
    assert rows[0][5] == claims[0].lease_token


def test_claim_leases_oldest_records_in_deterministic_order(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    _promote(_governed_service(scenario), scenario)
    key = PrivateKey()
    scenario.current_time += 5
    _promote(_rotate_to_new_key(scenario, key), scenario)
    ledger = _ledger_path(scenario)
    rows = _outbox_rows(ledger)
    assert len(rows) == 2
    key_hex = PublicKeyXOnly.from_secret(key.secret).format().hex()
    outbox = _claim_service(scenario, key_hex=key_hex).outbox()

    first = outbox.claim(current_time=scenario.current_time, lease_seconds=60)
    second = outbox.claim(current_time=scenario.current_time, lease_seconds=60)

    assert first is not None
    assert second is not None
    assert first.approval_id == rows[0][0]
    assert second.approval_id == rows[1][0]
    assert first.approval_id.hex() == scenario.vector["approval_id_hex"]
    assert outbox.claim(current_time=scenario.current_time, lease_seconds=60) is None


def test_expired_lease_is_claimable_again(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    _promote(_governed_service(scenario), scenario)
    outbox = _claim_service(scenario).outbox()

    first = outbox.claim(current_time=scenario.current_time, lease_seconds=30)
    assert first is not None
    assert (
        outbox.claim(current_time=scenario.current_time + 29, lease_seconds=30) is None
    )
    second = outbox.claim(current_time=scenario.current_time + 30, lease_seconds=30)

    assert second is not None
    assert second.lease_token != first.lease_token
    assert second.approval_id == first.approval_id
    assert second.lease_expires_at == scenario.current_time + 60


def test_lease_never_extends_past_retention_deadline(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    _promote(_governed_service(scenario, retention_max_retention_seconds=10), scenario)

    claim = (
        _claim_service(scenario)
        .outbox()
        .claim(
            current_time=scenario.current_time,
            lease_seconds=MAX_OUTBOX_LEASE_SECONDS,
        )
    )

    assert claim is not None
    assert claim.lease_expires_at == scenario.current_time + 10


def test_retention_cleanup_removes_deadline_passed_records_at_enqueue(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    _promote(_governed_service(scenario, retention_max_retention_seconds=10), scenario)
    ledger = _ledger_path(scenario)
    first_id = bytes.fromhex(scenario.vector["approval_id_hex"])
    claim = (
        _claim_service(scenario)
        .outbox()
        .claim(
            current_time=scenario.current_time,
            lease_seconds=MAX_OUTBOX_LEASE_SECONDS,
        )
    )
    assert claim is not None
    assert claim.lease_expires_at == scenario.current_time + 10

    scenario.current_time += 20
    _promote(
        _rotate_to_new_key(scenario, PrivateKey(), retention_max_retention_seconds=10),
        scenario,
    )

    rows = _outbox_rows(ledger)
    assert len(rows) == 1
    assert rows[0][0] != first_id
    assert rows[0][3] == scenario.current_time
    assert rows[0][4] == scenario.current_time + 10


def test_claim_atomically_purges_deadline_passed_records(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    _promote(_governed_service(scenario, retention_max_retention_seconds=10), scenario)
    ledger = _ledger_path(scenario)
    assert len(_outbox_rows(ledger)) == 1

    claim = (
        _claim_service(scenario)
        .outbox()
        .claim(current_time=scenario.current_time + 10, lease_seconds=60)
    )

    assert claim is None
    assert _outbox_rows(ledger) == []


def test_schema_rejects_lease_past_retention_deadline(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    _promote(_governed_service(scenario, retention_max_retention_seconds=10), scenario)
    ledger = _ledger_path(scenario)

    with sqlite3.connect(ledger) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                UPDATE approval_outbox
                SET lease_token = ?, lease_expires_at = retention_deadline + 1
                """,
                (b"\x11" * 32,),
            )

    rows = _outbox_rows(ledger)
    assert rows[0][5] is None
    assert rows[0][6] is None


def test_v4_acknowledge_cannot_delete_without_durable_result(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    _promote(_governed_service(scenario), scenario)
    outbox = _claim_service(scenario).outbox()
    claim = outbox.claim(current_time=scenario.current_time, lease_seconds=60)
    assert claim is not None
    ledger = _ledger_path(scenario)

    with pytest.raises(ObservableApprovalOutboxError):
        outbox.acknowledge(approval_id=claim.approval_id, lease_token=b"\x00" * 32)
    with pytest.raises(ObservableApprovalOutboxError):
        outbox.acknowledge(approval_id=b"\x00" * 32, lease_token=claim.lease_token)
    assert len(_outbox_rows(ledger)) == 1

    with pytest.raises(ObservableApprovalOutboxError):
        outbox.acknowledge(approval_id=claim.approval_id, lease_token=claim.lease_token)
    assert len(_outbox_rows(ledger)) == 1


def test_v1_migration_preserves_consumption_and_enables_outbox(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    legacy = ObservableApprovalConsumptionService(
        _write_consumption_policy(scenario.directory, scenario.vector)
    )
    legacy.consume(
        scenario.approval_wire,
        scenario.bundle_wire,
        report_nonce=scenario.report_nonce,
        current_time=scenario.current_time,
    )
    ledger = _ledger_path(scenario)
    assert _schema_version(ledger) == 1

    service = _governed_service(scenario)
    assert _schema_version(ledger) == 4
    assert "approval_outbox" in _table_names(ledger)
    with pytest.raises(ThreatHintV2PromotionReplayError):
        _promote(service, scenario)
    assert _outbox_rows(ledger) == []
    assert _consumption_count(ledger) == 1
    assert _high_water(ledger) == scenario.current_time

    scenario.current_time += 5
    _promote(_rotate_to_new_key(scenario, PrivateKey(), epoch=1), scenario)
    assert _consumption_count(ledger) == 2
    assert len(_outbox_rows(ledger)) == 1


def test_v2_migration_preserves_consumption_high_water_and_authority(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    ledger = _create_v2_ledger(scenario)
    assert _schema_version(ledger) == 2

    service = _governed_service(scenario)
    assert _schema_version(ledger) == 4
    assert "approval_outbox" in _table_names(ledger)
    with pytest.raises(ThreatHintV2PromotionReplayError):
        _promote(service, scenario)
    assert _consumption_count(ledger) == 1
    assert _high_water(ledger) == scenario.current_time
    assert _authority_state(ledger) is None
    assert _outbox_rows(ledger) == []

    scenario.current_time += 5
    _promote(_rotate_to_new_key(scenario, PrivateKey(), epoch=1), scenario)
    assert _consumption_count(ledger) == 2
    assert len(_outbox_rows(ledger)) == 1


def test_empty_v3_outbox_migrates_to_v4_without_data_loss(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    ledger = _create_v3_ledger(scenario, pending=False)
    assert _schema_version(ledger) == 3
    assert _consumption_count(ledger) == 1

    _governed_service(scenario)

    assert _schema_version(ledger) == 4
    assert _consumption_count(ledger) == 1
    assert _high_water(ledger) == scenario.current_time
    assert _outbox_rows(ledger) == []
    assert _result_rows(ledger) == []
    assert {
        "approval_outbox",
        "observable_analysis_results",
    }.issubset(_table_names(ledger))


def test_nonempty_v3_outbox_fails_closed_and_leaves_database_unchanged(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    ledger = _create_v3_ledger(scenario, pending=True)
    before_rows = _outbox_rows(ledger)
    with sqlite3.connect(ledger) as connection:
        before_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'approval_outbox'"
        ).fetchone()

    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        _governed_service(scenario)

    assert _schema_version(ledger) == 3
    assert _outbox_rows(ledger) == before_rows
    assert "observable_analysis_results" not in _table_names(ledger)
    with sqlite3.connect(ledger) as connection:
        after_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'approval_outbox'"
        ).fetchone()
    assert after_sql == before_sql


@pytest.mark.parametrize("version", [0, 1, 2])
def test_preexisting_hidden_outbox_table_fails_closed(
    tmp_path: Path, version: int
) -> None:
    scenario = _Scenario(tmp_path)
    ledger = _ledger_path(scenario)
    if version == 1:
        ObservableApprovalConsumptionService(
            _write_consumption_policy(scenario.directory, scenario.vector)
        )
    elif version == 2:
        _create_v2_ledger(scenario)
    else:
        with sqlite3.connect(ledger):
            pass
        ledger.chmod(0o600)
    with sqlite3.connect(ledger) as connection:
        connection.execute("CREATE TABLE approval_outbox (injected INTEGER) STRICT")

    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        _governed_service(scenario)

    assert _schema_version(ledger) == version


def test_v3_wrong_outbox_shape_fails_closed(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    _governed_service(scenario)
    ledger = _ledger_path(scenario)
    with sqlite3.connect(ledger) as connection:
        connection.execute("DROP TABLE approval_outbox")
        connection.execute(
            "CREATE TABLE approval_outbox (approval_id BLOB PRIMARY KEY) STRICT"
        )

    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        _governed_service(scenario)

    assert _schema_version(ledger) == 4


def test_v4_downgrade_to_v2_with_outbox_fails_closed(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    _governed_service(scenario)
    ledger = _ledger_path(scenario)
    with sqlite3.connect(ledger) as connection:
        connection.execute("PRAGMA user_version = 2")

    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        _governed_service(scenario)

    assert _schema_version(ledger) == 2


def test_v4_downgrade_to_v3_shape_confusion_fails_closed(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    _governed_service(scenario)
    ledger = _ledger_path(scenario)
    with sqlite3.connect(ledger) as connection:
        connection.execute("PRAGMA user_version = 3")

    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        _governed_service(scenario)

    assert _schema_version(ledger) == 3
    assert "observable_analysis_results" in _table_names(ledger)


def test_claim_lock_is_retryable(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    _promote(_governed_service(scenario), scenario)
    outbox = _claim_service(scenario).outbox()
    ledger = _ledger_path(scenario)

    lock = sqlite3.connect(ledger, isolation_level=None)
    lock.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(ObservableApprovalBusyError):
            outbox.claim(current_time=scenario.current_time, lease_seconds=60)
    finally:
        lock.rollback()
        lock.close()
    claim = outbox.claim(current_time=scenario.current_time, lease_seconds=60)
    assert claim is not None


def test_claim_inputs_are_exact_bounded_and_redacted(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    _promote(_governed_service(scenario), scenario)
    outbox = _claim_service(scenario).outbox()

    bad_inputs = (
        {"current_time": 0, "lease_seconds": 60},
        {"current_time": "1", "lease_seconds": 60},
        {"current_time": scenario.current_time, "lease_seconds": 0},
        {
            "current_time": scenario.current_time,
            "lease_seconds": MAX_OUTBOX_LEASE_SECONDS + 1,
        },
        {"current_time": scenario.current_time, "lease_seconds": "60"},
        {"current_time": UINT64_MAX, "lease_seconds": 1},
    )
    for kwargs in bad_inputs:
        with pytest.raises(ObservableApprovalOutboxError) as exc_info:
            outbox.claim(**kwargs)  # type: ignore[arg-type]
        assert str(exc_info.value) == "observable approval outbox failure"
        assert scenario.vector["approval_id_hex"] not in str(exc_info.value)

    rows = _outbox_rows(_ledger_path(scenario))
    assert rows[0][5] is None
    assert rows[0][6] is None


def test_claim_random_source_failure_is_redacted_and_keeps_pending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scenario = _Scenario(tmp_path)
    _promote(_governed_service(scenario), scenario)
    outbox = _claim_service(scenario).outbox()

    def fail_random(_: int) -> bytes:
        raise OSError("random source detail")

    monkeypatch.setattr(consumption_module.os, "urandom", fail_random)
    with pytest.raises(
        ObservableApprovalOutboxError,
        match=r"^observable approval outbox failure$",
    ) as exc_info:
        outbox.claim(current_time=scenario.current_time, lease_seconds=60)

    assert "random source detail" not in str(exc_info.value)
    rows = _outbox_rows(_ledger_path(scenario))
    assert rows[0][5] is None
    assert rows[0][6] is None


@pytest.mark.parametrize(
    ("column", "tampered"),
    [
        ("observable_commitment", b"\x00" * 32),
        ("bundle_wire", b"{}"),
        ("statement_wire", b"{}"),
        ("statement_digest", b"\x00" * 32),
        ("report_nonce", b"\x00" * 32),
    ],
)
def test_claim_revalidates_every_v2_binding_and_rejects_tampering(
    tmp_path: Path,
    column: str,
    tampered: bytes,
) -> None:
    scenario = _Scenario(tmp_path)
    _promote(_governed_service(scenario), scenario)
    ledger = _ledger_path(scenario)
    assert column in {
        "observable_commitment",
        "bundle_wire",
        "statement_wire",
        "statement_digest",
        "report_nonce",
    }
    with sqlite3.connect(ledger) as connection:
        connection.execute(
            f"UPDATE approval_outbox SET {column} = ?",  # nosec B608
            (tampered,),
        )

    with pytest.raises(
        ObservableApprovalOutboxError,
        match=r"^observable approval outbox failure$",
    ):
        _claim_service(scenario).outbox().claim(
            current_time=scenario.current_time,
            lease_seconds=60,
        )

    rows = _outbox_rows(ledger)
    assert len(rows) == 1
    assert rows[0][5] is None
    assert rows[0][6] is None


def test_acknowledge_inputs_are_exact_and_redacted(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    _promote(_governed_service(scenario), scenario)
    outbox = _claim_service(scenario).outbox()
    claim = outbox.claim(current_time=scenario.current_time, lease_seconds=60)
    assert claim is not None

    bad_inputs = (
        (claim.approval_id.hex(), claim.lease_token),
        (claim.approval_id, claim.lease_token.hex()),
        (b"\x00" * 31, claim.lease_token),
        (claim.approval_id, b"\x00" * 31),
        (None, claim.lease_token),
    )
    for approval_id, lease_token in bad_inputs:
        with pytest.raises(ObservableApprovalOutboxError) as exc_info:
            outbox.acknowledge(  # type: ignore[arg-type]
                approval_id=approval_id, lease_token=lease_token
            )
        assert str(exc_info.value) == "observable approval outbox failure"

    assert len(_outbox_rows(_ledger_path(scenario))) == 1


def test_claim_result_is_restricted_and_not_serializable(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    _promote(_governed_service(scenario), scenario)
    claim = (
        _claim_service(scenario)
        .outbox()
        .claim(current_time=scenario.current_time, lease_seconds=60)
    )
    assert claim is not None

    with pytest.raises(TypeError):
        ObservableApprovalOutboxClaim()
    with pytest.raises(TypeError):
        dataclasses.replace(claim)
    with pytest.raises(TypeError):
        pickle.dumps(claim)
    with pytest.raises(dataclasses.FrozenInstanceError):
        claim.lease_expires_at = 0  # type: ignore[misc]
    rendered = repr(claim)
    assert scenario.vector["approval_id_hex"] not in rendered
    assert scenario.vector["observable_commitment_hex"] not in rendered
    assert claim.lease_token.hex() not in rendered
    assert {field.name for field in dataclasses.fields(claim)} == {
        "approval_id",
        "observable_commitment",
        "bundle_wire",
        "statement_wire",
        "statement_digest",
        "report_nonce",
        "lease_token",
        "lease_expires_at",
        "input_identity",
    }


def test_failed_proof_creates_no_outbox_record(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    service = _governed_service(scenario, verifier_body="/bin/cat >/dev/null\nexit 1")

    with pytest.raises(ThreatHintV2PromotionError):
        _promote(service, scenario)

    ledger = _ledger_path(scenario)
    assert _outbox_rows(ledger) == []
    assert _consumption_count(ledger) == 0
    assert _high_water(ledger) == 0


def test_failed_promotion_restriction_creates_no_outbox_record(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    service = _governed_service(scenario, kinds=("file_sha256",))

    with pytest.raises(ThreatHintV2PromotionError):
        _promote(service, scenario)

    ledger = _ledger_path(scenario)
    assert _outbox_rows(ledger) == []
    assert _consumption_count(ledger) == 0
    assert _high_water(ledger) == 0
