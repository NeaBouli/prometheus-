"""Tests for the local durable Observable Approval consumption boundary."""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from coincurve import PrivateKey, PublicKeyXOnly

from jaeger.observable_approval import APPROVAL_SIGNING_DOMAIN
from jaeger.observable_approval_consumption import (
    ObservableApprovalBusyError,
    ObservableApprovalConsumptionError,
    ObservableApprovalConsumptionReceipt,
    ObservableApprovalConsumptionService,
    ObservableApprovalReplayError,
    load_observable_approval_policy,
)
from jaeger.threat_observable import ObservableBundle

_VECTOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "threat-hint"
    / "tests"
    / "vectors"
    / "threat-observable-approval-v1.json"
)


def _vector() -> dict:
    return json.loads(_VECTOR_PATH.read_text(encoding="utf-8"))


def _owner_directory(tmp_path: Path, name: str = "state") -> Path:
    directory = tmp_path / name
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    return directory


# pylint: disable-next=too-many-arguments
def _write_policy(
    directory: Path,
    vector: dict,
    *,
    key_hex: str | None = None,
    scope_hex: str | None = None,
    network_id: str | None = None,
    ledger_path: Path | None = None,
    suffix: str = "",
) -> Path:
    policy_path = directory / f"approval-policy{suffix}.toml"
    ledger = ledger_path or directory / f"approval-consumption{suffix}.sqlite3"
    policy_path.write_text(
        "\n".join(
            (
                "schema_version = 1",
                f'network_id = "{network_id or vector["network_id"]}"',
                "approver_xonly_public_key = "
                f'"{key_hex or vector["trusted_approver_xonly_public_key_hex"]}"',
                "recipient_scope = "
                f'"{scope_hex or vector["trusted_recipient_scope_hex"]}"',
                f'ledger_path = "{ledger}"',
                "",
            )
        ),
        encoding="ascii",
    )
    policy_path.chmod(0o600)
    return policy_path


def _fixture_inputs(vector: dict) -> tuple[bytes, bytes, bytes, int]:
    return (
        bytes.fromhex(vector["approval_wire_hex"]),
        bytes.fromhex(vector["bundle_wire_hex"]),
        bytes.fromhex(vector["report_nonce_hex"]),
        vector["current_time"],
    )


# pylint: disable-next=too-many-arguments
def _consume(
    service: ObservableApprovalConsumptionService,
    vector: dict,
    *,
    approval_wire: bytes | None = None,
    bundle_wire: bytes | None = None,
    report_nonce: bytes | None = None,
    current_time: int | None = None,
) -> ObservableApprovalConsumptionReceipt:
    fixture_approval, fixture_bundle, fixture_nonce, fixture_time = _fixture_inputs(
        vector
    )
    return service.consume(
        fixture_approval if approval_wire is None else approval_wire,
        fixture_bundle if bundle_wire is None else bundle_wire,
        report_nonce=fixture_nonce if report_nonce is None else report_nonce,
        current_time=fixture_time if current_time is None else current_time,
    )


def _domain_digest(domain: bytes, value: bytes) -> bytes:
    digest = hashlib.sha256()
    digest.update(domain)
    digest.update(len(value).to_bytes(4, byteorder="big", signed=False))
    digest.update(value)
    return digest.digest()


def _signed_approval(
    vector: dict,
    key: PrivateKey,
    *,
    approval_nonce: bytes,
    not_before: int = 100,
    expires_at: int = 1_000,
) -> bytes:
    key_hex = PublicKeyXOnly.from_secret(key.secret).format().hex()
    bundle = ObservableBundle.parse_canonical(bytes.fromhex(vector["bundle_wire_hex"]))
    body = {
        "schema_version": 1,
        "observable_commitment": bundle.commitment(
            vector["network_id"], vector["report_nonce_hex"]
        ).hex(),
        "approver_xonly_public_key": key_hex,
        "purpose": "guardian_analysis_v1",
        "recipient_scope": vector["trusted_recipient_scope_hex"],
        "network_id": vector["network_id"],
        "not_before": not_before,
        "expires_at": expires_at,
        "approval_nonce": approval_nonce.hex(),
    }
    body_wire = json.dumps(body, separators=(",", ":")).encode("ascii")
    signature = key.sign_schnorr(_domain_digest(APPROVAL_SIGNING_DOMAIN, body_wire))
    return json.dumps(
        {**body, "signature": signature.hex()}, separators=(",", ":")
    ).encode("ascii")


def _consumption_count(ledger_path: Path) -> int:
    with sqlite3.connect(ledger_path) as connection:
        return connection.execute(
            "SELECT COUNT(*) FROM approval_consumptions"
        ).fetchone()[0]


def test_valid_approval_is_consumed_once_and_rejected_after_restart(
    tmp_path: Path,
) -> None:
    vector = _vector()
    directory = _owner_directory(tmp_path)
    policy_path = _write_policy(directory, vector)

    receipt = _consume(ObservableApprovalConsumptionService(policy_path), vector)

    assert receipt.approval_id.hex() == vector["approval_id_hex"]
    assert receipt.observable_commitment.hex() == vector["observable_commitment_hex"]
    assert receipt.consumed_at == vector["current_time"]
    with pytest.raises(ObservableApprovalReplayError):
        _consume(ObservableApprovalConsumptionService(policy_path), vector)
    assert _consumption_count(directory / "approval-consumption.sqlite3") == 1


def test_concurrent_duplicate_has_exactly_one_winner(tmp_path: Path) -> None:
    vector = _vector()
    directory = _owner_directory(tmp_path)
    policy_path = _write_policy(directory, vector)
    services = (
        ObservableApprovalConsumptionService(policy_path),
        ObservableApprovalConsumptionService(policy_path),
    )

    def attempt(service: ObservableApprovalConsumptionService) -> str:
        for _ in range(3):
            try:
                _consume(service, vector)
                return "consumed"
            except ObservableApprovalReplayError:
                return "replay"
            except ObservableApprovalBusyError:
                time.sleep(0.01)
        return "busy"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, services))

    assert sorted(outcomes) == ["consumed", "replay"]
    assert _consumption_count(directory / "approval-consumption.sqlite3") == 1


def test_authority_nonce_cannot_be_reused_in_distinct_valid_statement(
    tmp_path: Path,
) -> None:
    vector = _vector()
    key = PrivateKey()
    key_hex = PublicKeyXOnly.from_secret(key.secret).format().hex()
    directory = _owner_directory(tmp_path)
    policy_path = _write_policy(directory, vector, key_hex=key_hex)
    service = ObservableApprovalConsumptionService(policy_path)
    first = _signed_approval(vector, key, approval_nonce=b"\x91" * 32)
    second = _signed_approval(
        vector,
        key,
        approval_nonce=b"\x91" * 32,
        not_before=101,
    )

    _consume(service, vector, approval_wire=first, current_time=500)
    with pytest.raises(ObservableApprovalReplayError):
        _consume(service, vector, approval_wire=second, current_time=500)


@pytest.mark.parametrize(
    ("policy_changes", "consume_changes"),
    [
        ({"key_hex": "55" * 32}, {}),
        ({"scope_hex": "66" * 32}, {}),
        ({"network_id": "mainnet"}, {}),
        ({}, {"report_nonce": b"\x44" * 32}),
        ({}, {"current_time": 1_700_003_601}),
        ({}, {"bundle_wire": b'{"schema_version":1}'}),
    ],
)
def test_failed_verification_never_writes_consumption(
    tmp_path: Path,
    policy_changes: dict,
    consume_changes: dict,
) -> None:
    vector = _vector()
    directory = _owner_directory(tmp_path)
    policy_path = _write_policy(directory, vector, **policy_changes)
    service = ObservableApprovalConsumptionService(policy_path)

    with pytest.raises(
        ObservableApprovalConsumptionError,
        match=r"^observable approval was not consumed$",
    ):
        _consume(service, vector, **consume_changes)
    assert _consumption_count(directory / "approval-consumption.sqlite3") == 0


def test_sqlite_lock_is_retryable_without_consuming(tmp_path: Path) -> None:
    vector = _vector()
    directory = _owner_directory(tmp_path)
    policy_path = _write_policy(directory, vector)
    service = ObservableApprovalConsumptionService(policy_path)
    ledger_path = directory / "approval-consumption.sqlite3"
    lock = sqlite3.connect(ledger_path, isolation_level=None)
    lock.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(ObservableApprovalBusyError):
            _consume(service, vector)
    finally:
        lock.rollback()
        lock.close()

    _consume(service, vector)
    assert _consumption_count(ledger_path) == 1


def test_constructor_lock_is_retryable_without_initializing_schema(
    tmp_path: Path,
) -> None:
    vector = _vector()
    directory = _owner_directory(tmp_path)
    ledger_path = directory / "approval-consumption.sqlite3"
    with sqlite3.connect(ledger_path):
        pass
    ledger_path.chmod(0o600)
    policy_path = _write_policy(directory, vector, ledger_path=ledger_path)
    lock = sqlite3.connect(ledger_path, isolation_level=None)
    lock.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(ObservableApprovalBusyError):
            ObservableApprovalConsumptionService(policy_path)
    finally:
        lock.rollback()
        lock.close()

    _consume(ObservableApprovalConsumptionService(policy_path), vector)
    assert _consumption_count(ledger_path) == 1


def test_integrity_failure_rolls_back_high_water_and_is_not_replay(
    tmp_path: Path,
) -> None:
    vector = _vector()
    directory = _owner_directory(tmp_path)
    policy_path = _write_policy(directory, vector)
    service = ObservableApprovalConsumptionService(policy_path)
    ledger_path = directory / "approval-consumption.sqlite3"
    with sqlite3.connect(ledger_path) as connection:
        connection.execute("""
            CREATE TRIGGER reject_consumption
            BEFORE INSERT ON approval_consumptions
            BEGIN
                SELECT RAISE(ABORT, 'injected failure');
            END
            """)

    with pytest.raises(ObservableApprovalConsumptionError) as exc_info:
        _consume(service, vector)
    assert exc_info.type is ObservableApprovalConsumptionError
    assert _consumption_count(ledger_path) == 0

    with sqlite3.connect(ledger_path) as connection:
        high_water = connection.execute(
            "SELECT high_water_seconds FROM ledger_state WHERE singleton = 1"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER reject_consumption")
    assert high_water == 0
    _consume(service, vector)


def test_persistent_clock_high_water_rejects_rollback(tmp_path: Path) -> None:
    vector = _vector()
    key = PrivateKey()
    directory = _owner_directory(tmp_path)
    policy_path = _write_policy(
        directory,
        vector,
        key_hex=PublicKeyXOnly.from_secret(key.secret).format().hex(),
    )
    service = ObservableApprovalConsumptionService(policy_path)
    first = _signed_approval(vector, key, approval_nonce=b"\xa1" * 32)
    second = _signed_approval(vector, key, approval_nonce=b"\xa2" * 32)

    _consume(service, vector, approval_wire=first, current_time=500)
    with pytest.raises(ObservableApprovalReplayError):
        _consume(
            ObservableApprovalConsumptionService(policy_path),
            vector,
            approval_wire=second,
            current_time=499,
        )
    assert _consumption_count(directory / "approval-consumption.sqlite3") == 1


@pytest.mark.parametrize(
    "replacement",
    [
        "schema_version = 1\nunexpected = true\n",
        "schema_version = 2\n",
    ],
)
def test_policy_rejects_non_exact_schema(tmp_path: Path, replacement: str) -> None:
    directory = _owner_directory(tmp_path)
    policy_path = directory / "policy.toml"
    policy_path.write_text(replacement, encoding="ascii")
    policy_path.chmod(0o600)

    with pytest.raises(ObservableApprovalConsumptionError):
        load_observable_approval_policy(policy_path)


def test_policy_rejects_malformed_values_and_unsafe_paths(tmp_path: Path) -> None:
    vector = _vector()
    directory = _owner_directory(tmp_path)
    cases = (
        {"key_hex": "AA" * 32, "suffix": "-uppercase"},
        {"scope_hex": "00", "suffix": "-short"},
        {"network_id": "INVALID!", "suffix": "-network"},
        {"ledger_path": Path("relative.sqlite3"), "suffix": "-relative"},
    )
    for changes in cases:
        policy_path = _write_policy(directory, vector, **changes)
        with pytest.raises(ObservableApprovalConsumptionError):
            load_observable_approval_policy(policy_path)

    unsafe_policy = _write_policy(directory, vector, suffix="-mode")
    unsafe_policy.chmod(0o640)
    with pytest.raises(ObservableApprovalConsumptionError):
        load_observable_approval_policy(unsafe_policy)

    target = _write_policy(directory, vector, suffix="-target")
    policy_link = directory / "policy-link.toml"
    policy_link.symlink_to(target)
    with pytest.raises(ObservableApprovalConsumptionError):
        load_observable_approval_policy(policy_link)


def test_policy_file_path_must_be_absolute() -> None:
    with pytest.raises(
        ObservableApprovalConsumptionError,
        match=r"^observable approval was not consumed$",
    ):
        load_observable_approval_policy(Path("relative-policy.toml"))


def test_ledger_requires_owner_only_regular_path(tmp_path: Path) -> None:
    vector = _vector()
    unsafe_parent = tmp_path / "unsafe"
    unsafe_parent.mkdir(mode=0o755)
    unsafe_parent.chmod(0o755)
    safe_policy_dir = _owner_directory(tmp_path, "policies")
    policy_path = _write_policy(
        safe_policy_dir,
        vector,
        ledger_path=unsafe_parent / "ledger.sqlite3",
    )
    with pytest.raises(ObservableApprovalConsumptionError):
        ObservableApprovalConsumptionService(policy_path)

    safe_state = _owner_directory(tmp_path, "safe-state")
    target = safe_state / "target.sqlite3"
    target.touch(mode=0o600)
    ledger_link = safe_state / "ledger-link.sqlite3"
    ledger_link.symlink_to(target)
    link_policy = _write_policy(
        safe_policy_dir,
        vector,
        ledger_path=ledger_link,
        suffix="-link",
    )
    with pytest.raises(ObservableApprovalConsumptionError):
        ObservableApprovalConsumptionService(link_policy)

    target.chmod(0o640)
    file_policy = _write_policy(
        safe_policy_dir,
        vector,
        ledger_path=target,
        suffix="-file-mode",
    )
    with pytest.raises(ObservableApprovalConsumptionError):
        ObservableApprovalConsumptionService(file_policy)


@pytest.mark.parametrize("ledger_bytes", [b"not sqlite", None])
def test_existing_ledger_corruption_or_unknown_schema_fails_closed(
    tmp_path: Path,
    ledger_bytes: bytes | None,
) -> None:
    vector = _vector()
    directory = _owner_directory(tmp_path)
    ledger_path = directory / "approval-consumption.sqlite3"
    if ledger_bytes is None:
        with sqlite3.connect(ledger_path) as connection:
            connection.execute("PRAGMA user_version = 99")
    else:
        ledger_path.write_bytes(ledger_bytes)
    ledger_path.chmod(0o600)
    policy_path = _write_policy(directory, vector, ledger_path=ledger_path)

    with pytest.raises(ObservableApprovalConsumptionError) as exc_info:
        ObservableApprovalConsumptionService(policy_path)
    assert exc_info.type is ObservableApprovalConsumptionError
    assert str(exc_info.value) == "observable approval was not consumed"


def test_existing_version_zero_wrong_schema_fails_closed(tmp_path: Path) -> None:
    vector = _vector()
    directory = _owner_directory(tmp_path)
    ledger_path = directory / "approval-consumption.sqlite3"
    with sqlite3.connect(ledger_path) as connection:
        connection.execute(
            "CREATE TABLE approval_consumptions (approval_id BLOB) STRICT"
        )
    ledger_path.chmod(0o600)
    policy_path = _write_policy(directory, vector, ledger_path=ledger_path)

    with pytest.raises(ObservableApprovalConsumptionError) as exc_info:
        ObservableApprovalConsumptionService(policy_path)
    assert exc_info.type is ObservableApprovalConsumptionError
    assert str(exc_info.value) == "observable approval was not consumed"


def test_public_service_api_cannot_accept_preverified_or_policy_fields() -> None:
    parameters = set(
        inspect.signature(ObservableApprovalConsumptionService.consume).parameters
    )
    assert parameters == {
        "self",
        "approval_wire",
        "bundle_wire",
        "report_nonce",
        "current_time",
    }
    assert "verified" not in parameters
    assert "network_id" not in parameters
    assert "approver_xonly_public_key" not in parameters
    assert "recipient_scope" not in parameters


def test_closed_errors_do_not_disclose_policy_values(tmp_path: Path) -> None:
    directory = _owner_directory(tmp_path)
    marker = "secret-policy-marker"
    policy_path = directory / "policy.toml"
    policy_path.write_text(marker, encoding="ascii")
    policy_path.chmod(0o600)

    with pytest.raises(ObservableApprovalConsumptionError) as exc_info:
        load_observable_approval_policy(policy_path)
    assert str(exc_info.value) == "observable approval was not consumed"
    assert marker not in str(exc_info.value)


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes are required")
def test_policy_parent_must_be_owner_only(tmp_path: Path) -> None:
    vector = _vector()
    directory = tmp_path / "shared"
    directory.mkdir(mode=0o755)
    directory.chmod(0o755)
    policy_path = _write_policy(directory, vector)

    with pytest.raises(ObservableApprovalConsumptionError):
        load_observable_approval_policy(policy_path)
