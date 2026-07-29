"""Tests for the local fail-closed ThreatHint-v2 acceptance boundary."""

# Pytest test names provide the scenario descriptions; tests intentionally
# exercise private service state for lock and ledger adversarial coverage.
# pylint: disable=missing-function-docstring,protected-access

from __future__ import annotations

import dataclasses
import hashlib
import inspect
import os
import pickle
import shlex
import sqlite3
import stat
import threading
import time
from pathlib import Path
from typing import Any

import pytest

import jaeger.threat_hint_v2_acceptance as acceptance_module
from jaeger.threat_hint_v2_acceptance import (
    ThreatHintV2AcceptanceBusyError,
    ThreatHintV2AcceptanceError,
    ThreatHintV2AcceptanceReceipt,
    ThreatHintV2AcceptanceReplayError,
    ThreatHintV2AcceptanceService,
    ThreatHintV2AcceptanceUnavailableError,
)
from jaeger.threat_hint_v2_statement import STATEMENT_DIGEST_DOMAIN
from tests.test_threat_hint_v2_preflight import _Scenario
from tests.test_threat_hint_v2_verified_preflight import (
    _write_config,
    _write_owner_file,
    _write_verifier,
)

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="acceptance requires POSIX process controls"
)


def _write_consumption_policy(
    directory: Path,
    vector: dict,
    *,
    key_hex: str | None = None,
    scope_hex: str | None = None,
    network_id: str | None = None,
    ledger_name: str = "acceptance.sqlite3",
    name: str = "consumption-policy.toml",
) -> Path:
    wire = "\n".join(
        (
            "schema_version = 1",
            f'network_id = "{network_id or vector["network_id"]}"',
            "approver_xonly_public_key = "
            f'"{key_hex or vector["trusted_approver_xonly_public_key_hex"]}"',
            f'recipient_scope = "{scope_hex or vector["trusted_recipient_scope_hex"]}"',
            f'ledger_path = "{directory / ledger_name}"',
            "",
        )
    ).encode("ascii")
    return _write_owner_file(directory / name, wire)


def _service(
    scenario: _Scenario,
    body: str = "/bin/cat >/dev/null\nexit 0",
    *,
    timeout_ms: int = 30_000,
    **policy_changes: Any,
) -> ThreatHintV2AcceptanceService:
    manifest = _write_owner_file(
        scenario.directory / "relation-manifest-v2.json",
        scenario.manifest_wire,
    )
    executable = _write_verifier(scenario.directory, body)
    config = _write_config(
        scenario.directory, executable, manifest, timeout_ms=timeout_ms
    )
    consumption_policy = _write_consumption_policy(
        scenario.directory, scenario.vector, **policy_changes
    )
    return ThreatHintV2AcceptanceService(
        config, scenario.policy_path, consumption_policy
    )


def _accept(
    service: ThreatHintV2AcceptanceService,
    scenario: _Scenario,
    **changes: Any,
) -> ThreatHintV2AcceptanceReceipt:
    values = {
        "envelope_wire": scenario.envelope_wire,
        "bundle_wire": scenario.bundle_wire,
        "approval_wire": scenario.approval_wire,
        "report_nonce": scenario.report_nonce,
        "current_time": scenario.current_time,
    }
    values.update(changes)
    return service.accept(
        values["envelope_wire"],
        values["bundle_wire"],
        values["approval_wire"],
        report_nonce=values["report_nonce"],
        current_time=values["current_time"],
    )


def _ledger_path(scenario: _Scenario) -> Path:
    return scenario.directory / "acceptance.sqlite3"


def _consumption_count(ledger_path: Path) -> int:
    with sqlite3.connect(ledger_path) as connection:
        return connection.execute(
            "SELECT COUNT(*) FROM approval_consumptions"
        ).fetchone()[0]


def _high_water(ledger_path: Path) -> int:
    with sqlite3.connect(ledger_path) as connection:
        return connection.execute(
            "SELECT high_water_seconds FROM ledger_state WHERE singleton = 1"
        ).fetchone()[0]


def test_valid_accept_verifies_first_and_consumes_exactly_once(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    service = _service(scenario)

    receipt = _accept(service, scenario)

    vector = scenario.vector
    expected_digest = hashlib.sha256()
    expected_digest.update(STATEMENT_DIGEST_DOMAIN)
    expected_digest.update(
        len(scenario.statement_wire).to_bytes(4, byteorder="big", signed=False)
    )
    expected_digest.update(scenario.statement_wire)
    assert receipt.statement_digest == expected_digest.digest()
    assert receipt.approval_id.hex() == vector["approval_id_hex"]
    assert receipt.observable_commitment.hex() == vector["observable_commitment_hex"]
    assert receipt.consumed_at == vector["current_time"]
    assert receipt.raw_manifest_sha256_hex == scenario.anchor_hex
    assert (
        receipt.envelope_sha256_hex
        == hashlib.sha256(scenario.envelope_wire).hexdigest()
    )
    assert {field.name for field in dataclasses.fields(receipt)} == {
        "statement_digest",
        "approval_id",
        "observable_commitment",
        "consumed_at",
        "raw_manifest_sha256_hex",
        "envelope_sha256_hex",
        "verifier_executable_sha256_hex",
    }
    assert _consumption_count(_ledger_path(scenario)) == 1
    assert _high_water(_ledger_path(scenario)) == vector["current_time"]


def test_replay_is_final_and_survives_restart(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    _accept(_service(scenario), scenario)

    with pytest.raises(
        ThreatHintV2AcceptanceReplayError,
        match=r"^threat-hint v2 acceptance replay$",
    ):
        _accept(_service(scenario), scenario)
    assert _consumption_count(_ledger_path(scenario)) == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"report_nonce": b"\x44" * 32},
        {"envelope_wire": b"not json"},
        {"bundle_wire": b'{"schema_version":1}'},
        {"approval_wire": b"not json"},
        {"current_time": 0},
        {"envelope_wire": "text"},
    ],
)
def test_invalid_candidate_never_consumes_or_advances_high_water(
    tmp_path: Path, changes: dict
) -> None:
    scenario = _Scenario(tmp_path)
    service = _service(scenario)

    with pytest.raises(
        ThreatHintV2AcceptanceError, match=r"^invalid threat-hint v2 acceptance$"
    ):
        _accept(service, scenario, **changes)
    assert _consumption_count(_ledger_path(scenario)) == 0
    assert _high_water(_ledger_path(scenario)) == 0


def test_failed_proof_never_consumes_or_advances_high_water(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    service = _service(scenario, "/bin/cat >/dev/null\nexit 1")

    with pytest.raises(
        ThreatHintV2AcceptanceError, match=r"^invalid threat-hint v2 acceptance$"
    ):
        _accept(service, scenario)
    assert _consumption_count(_ledger_path(scenario)) == 0
    assert _high_water(_ledger_path(scenario)) == 0


def test_unavailable_verifier_never_consumes(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    service = _service(scenario, "/bin/cat >/dev/null\nexit 2")

    with pytest.raises(
        ThreatHintV2AcceptanceUnavailableError,
        match=r"^threat-hint v2 acceptance unavailable$",
    ):
        _accept(service, scenario)
    assert _consumption_count(_ledger_path(scenario)) == 0
    assert _high_water(_ledger_path(scenario)) == 0


def test_verifier_timeout_is_unavailable_and_never_consumes(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    service = _service(scenario, "/bin/sleep 30\nexit 0", timeout_ms=1_000)

    with pytest.raises(ThreatHintV2AcceptanceUnavailableError):
        _accept(service, scenario)
    assert _consumption_count(_ledger_path(scenario)) == 0
    assert _high_water(_ledger_path(scenario)) == 0


def test_busy_verifier_slot_is_retryable_without_consumption(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    started = scenario.directory / "started"
    release = scenario.directory / "release"
    body = f"""
printf 'started\\n' >> {shlex.quote(str(started))}
while [ ! -f {shlex.quote(str(release))} ]; do /bin/sleep 0.02; done
/bin/cat >/dev/null
exit 0
"""
    service = _service(scenario, body)
    result: list[ThreatHintV2AcceptanceReceipt] = []
    errors: list[BaseException] = []

    def first_call() -> None:
        try:
            result.append(_accept(service, scenario))
        except BaseException as error:  # pragma: no cover - assertion captures
            errors.append(error)

    worker = threading.Thread(target=first_call)
    worker.start()
    deadline = time.monotonic() + 15
    while not started.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert started.exists()

    with pytest.raises(
        ThreatHintV2AcceptanceBusyError,
        match=r"^threat-hint v2 acceptance busy$",
    ):
        _accept(service, scenario)
    release.touch(mode=0o600)
    worker.join(timeout=15)

    assert not worker.is_alive()
    assert errors == []
    assert len(result) == 1
    assert _consumption_count(_ledger_path(scenario)) == 1


def test_busy_ledger_is_retryable_without_consumption(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    service = _service(scenario)
    ledger_path = _ledger_path(scenario)
    lock = sqlite3.connect(ledger_path, isolation_level=None)
    lock.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(
            ThreatHintV2AcceptanceBusyError,
            match=r"^threat-hint v2 acceptance busy$",
        ):
            _accept(service, scenario)
    finally:
        lock.rollback()
        lock.close()

    assert _consumption_count(ledger_path) == 0
    assert _high_water(ledger_path) == 0
    _accept(service, scenario)
    assert _consumption_count(ledger_path) == 1


def test_concurrent_duplicate_has_exactly_one_winner(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    service = _service(scenario)

    def attempt() -> str:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                _accept(service, scenario)
                return "consumed"
            except ThreatHintV2AcceptanceReplayError:
                return "replay"
            except ThreatHintV2AcceptanceBusyError:
                time.sleep(0.02)
        return "busy"

    outcomes: list[str] = []
    workers = [
        threading.Thread(target=lambda: outcomes.append(attempt())) for _ in range(2)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=30)

    assert all(not worker.is_alive() for worker in workers)
    assert sorted(outcomes) == ["consumed", "replay"]
    assert _consumption_count(_ledger_path(scenario)) == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"key_hex": "55" * 32},
        {"scope_hex": "66" * 32},
        {"network_id": "testnet-11"},
    ],
)
def test_policy_identity_mismatch_fails_before_ledger_creation(
    tmp_path: Path, changes: dict
) -> None:
    scenario = _Scenario(tmp_path)

    with pytest.raises(
        ThreatHintV2AcceptanceUnavailableError,
        match=r"^threat-hint v2 acceptance unavailable$",
    ):
        _service(scenario, **changes)
    assert not _ledger_path(scenario).exists()


def test_public_api_accepts_only_raw_wires_and_owner_paths() -> None:
    constructor = inspect.signature(ThreatHintV2AcceptanceService)
    assert set(constructor.parameters) == {
        "config_path",
        "preflight_policy_path",
        "consumption_policy_path",
    }
    call = inspect.signature(ThreatHintV2AcceptanceService.accept)
    assert set(call.parameters) == {
        "self",
        "envelope_wire",
        "bundle_wire",
        "approval_wire",
        "report_nonce",
        "current_time",
    }
    for forbidden in (
        "receipt",
        "verified",
        "policy",
        "manifest",
        "anchor",
        "statement",
        "network_id",
        "ledger_path",
    ):
        assert forbidden not in call.parameters
    source = inspect.getsource(acceptance_module)
    assert "\nimport sqlite3" not in source
    assert "\nfrom sqlite3" not in source
    assert "\nimport subprocess" not in source
    assert "\nfrom subprocess" not in source
    assert "shell=True" not in source


def test_receipt_is_restricted_data_and_not_serializable(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    receipt = _accept(_service(scenario), scenario)

    with pytest.raises(TypeError):
        ThreatHintV2AcceptanceReceipt()
    with pytest.raises(TypeError):
        dataclasses.replace(receipt)
    with pytest.raises(TypeError):
        pickle.dumps(receipt)
    forged = object.__new__(ThreatHintV2AcceptanceReceipt)
    with pytest.raises(AttributeError):
        _ = forged.statement_digest
    with pytest.raises(dataclasses.FrozenInstanceError):
        receipt.consumed_at = 0  # type: ignore[misc]
    rendered = repr(receipt)
    for sensitive in (
        scenario.vector["approval_id_hex"],
        scenario.vector["observable_commitment_hex"],
        scenario.anchor_hex,
        receipt.envelope_sha256_hex,
    ):
        assert sensitive not in rendered
    for forbidden in (
        "proof",
        "statement",
        "bundle",
        "approval",
        "consume",
        "verify",
        "policy",
        "approver_xonly_public_key",
        "recipient_scope",
    ):
        assert not hasattr(receipt, forbidden)


def test_errors_are_stable_and_redacted(tmp_path: Path) -> None:
    marker = "secret$acceptance-marker"
    scenario = _Scenario(tmp_path)
    manifest = _write_owner_file(
        scenario.directory / "relation-manifest-v2.json", scenario.manifest_wire
    )
    executable = _write_verifier(scenario.directory, "/bin/cat >/dev/null\nexit 0")
    config = _write_config(scenario.directory, executable, manifest)
    marked_policy = _write_owner_file(
        scenario.directory / "marked-policy.toml", marker.encode("ascii")
    )
    with pytest.raises(ThreatHintV2AcceptanceUnavailableError) as policy_error:
        ThreatHintV2AcceptanceService(config, scenario.policy_path, marked_policy)
    assert str(policy_error.value) == "threat-hint v2 acceptance unavailable"
    assert marker not in str(policy_error.value)

    service = _service(scenario)
    with pytest.raises(ThreatHintV2AcceptanceError) as accept_error:
        _accept(service, scenario, report_nonce=b"\x44" * 32)
    message = str(accept_error.value)
    assert message == "invalid threat-hint v2 acceptance"
    for sensitive in (
        scenario.vector["trusted_approver_xonly_public_key_hex"],
        scenario.vector["trusted_recipient_scope_hex"],
        scenario.vector["report_nonce_hex"],
        scenario.anchor_hex,
    ):
        assert sensitive not in message


def test_runtime_failure_does_not_mutate_service_files(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    service = _service(scenario)
    before = {
        str(path.relative_to(scenario.directory)): (
            stat.S_IMODE(path.stat().st_mode),
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for path in sorted(scenario.directory.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }
    with pytest.raises(ThreatHintV2AcceptanceError):
        _accept(service, scenario, report_nonce=b"\x44" * 32)
    after = {
        str(path.relative_to(scenario.directory)): (
            stat.S_IMODE(path.stat().st_mode),
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for path in sorted(scenario.directory.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }
    assert after == before
