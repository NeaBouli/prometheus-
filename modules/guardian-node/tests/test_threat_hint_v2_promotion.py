"""Tests for the local fail-closed ThreatHint-v2 promotion boundary."""

# Pytest test names provide the scenario descriptions; tests intentionally
# exercise private service state for lock and ledger adversarial coverage.
# pylint: disable=missing-function-docstring,protected-access,too-many-locals

from __future__ import annotations

import dataclasses
import hashlib
import inspect
import os
import pickle
import shlex
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable

import pytest

import jaeger.threat_hint_v2_promotion as promotion_module
from jaeger.threat_hint_v2_promotion import (
    MAX_PROMOTION_POLICY_BYTES,
    ThreatHintV2PromotionBusyError,
    ThreatHintV2PromotionError,
    ThreatHintV2PromotionReplayError,
    ThreatHintV2PromotionResult,
    ThreatHintV2PromotionService,
    ThreatHintV2PromotionUnavailableError,
)
from jaeger.threat_hint_v2_statement import STATEMENT_DIGEST_DOMAIN
from jaeger.threat_observable import MAX_OBSERVABLES
from tests.test_threat_hint_v2_acceptance import (
    _consumption_count,
    _high_water,
    _ledger_path,
    _write_consumption_policy,
)
from tests.test_threat_hint_v2_preflight import _PUBLIC_AUTO_BUNDLE, _Scenario
from tests.test_threat_hint_v2_verified_preflight import (
    _write_config,
    _write_owner_file,
    _write_verifier,
)

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="promotion requires POSIX process controls"
)

_TWO_OBSERVABLE_BUNDLE = (
    b'{"schema_version":1,"disclosure_policy":"review_required_v1",'
    b'"scope":{"platform":"linux","format":"elf"},'
    b'"observables":[{"kind":"api_import","value":"mmap"},'
    b'{"kind":"file_sha256","value":"' + b"ab" * 32 + b'"}]}'
)
_NONCANONICAL_BUNDLE = (
    b'{ "schema_version": 1, "disclosure_policy": "review_required_v1", '
    b'"scope": {"platform": "linux", "format": "elf"}, '
    b'"observables": [{"kind": "api_import", "value": "mmap"}] }'
)
_VALID_POLICY_TEXT = "\n".join(
    (
        "schema_version = 1",
        'scope_platform = "linux"',
        'scope_format = "elf"',
        'allowed_observable_kinds = ["api_import", "file_sha256"]',
        "max_observables = 16",
        "",
    )
)


class _BytesSubclass(bytes):
    pass


class _IntSubclass(int):
    pass


def _write_promotion_policy(
    directory: Path,
    *,
    platform: str = "linux",
    artifact_format: str = "elf",
    kinds: Iterable[str] = ("api_import", "file_sha256", "byte_pattern"),
    max_observables: int = MAX_OBSERVABLES,
    raw: bytes | None = None,
    name: str = "promotion-policy.toml",
) -> Path:
    if raw is None:
        kinds_text = ", ".join(f'"{kind}"' for kind in kinds)
        raw = "\n".join(
            (
                "schema_version = 1",
                f'scope_platform = "{platform}"',
                f'scope_format = "{artifact_format}"',
                f"allowed_observable_kinds = [{kinds_text}]",
                f"max_observables = {max_observables}",
                "",
            )
        ).encode("ascii")
    return _write_owner_file(directory / name, raw)


def _acceptance_paths(
    scenario: _Scenario,
    body: str = "/bin/cat >/dev/null\nexit 0",
    *,
    timeout_ms: int = 30_000,
    **consumption_changes: Any,
) -> tuple[Path, Path]:
    manifest = _write_owner_file(
        scenario.directory / "relation-manifest-v2.json", scenario.manifest_wire
    )
    executable = _write_verifier(scenario.directory, body)
    config = _write_config(
        scenario.directory, executable, manifest, timeout_ms=timeout_ms
    )
    consumption_policy = _write_consumption_policy(
        scenario.directory, scenario.vector, **consumption_changes
    )
    return config, consumption_policy


def _service(
    scenario: _Scenario,
    body: str = "/bin/cat >/dev/null\nexit 0",
    *,
    timeout_ms: int = 30_000,
    **promotion_changes: Any,
) -> ThreatHintV2PromotionService:
    config, consumption_policy = _acceptance_paths(
        scenario, body, timeout_ms=timeout_ms
    )
    promotion_policy = _write_promotion_policy(scenario.directory, **promotion_changes)
    return ThreatHintV2PromotionService(
        config, scenario.policy_path, consumption_policy, promotion_policy
    )


def _promote(
    service: ThreatHintV2PromotionService,
    scenario: _Scenario,
    **changes: Any,
) -> ThreatHintV2PromotionResult:
    values = {
        "envelope_wire": scenario.envelope_wire,
        "bundle_wire": scenario.bundle_wire,
        "approval_wire": scenario.approval_wire,
        "report_nonce": scenario.report_nonce,
        "current_time": scenario.current_time,
    }
    values.update(changes)
    return service.promote(
        values["envelope_wire"],
        values["bundle_wire"],
        values["approval_wire"],
        report_nonce=values["report_nonce"],
        current_time=values["current_time"],
    )


def _marker_body(marker: Path) -> str:
    return (
        f"printf 'ran\\n' >> {shlex.quote(str(marker))}\n" "/bin/cat >/dev/null\nexit 0"
    )


def test_valid_promote_returns_exact_result_and_consumes_once(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    service = _service(scenario)

    result = _promote(service, scenario)

    vector = scenario.vector
    assert (
        service._policy.policy_sha256
        == hashlib.sha256(  # pylint: disable=protected-access
            (scenario.directory / "promotion-policy.toml").read_bytes()
        ).digest()
    )
    expected_digest = hashlib.sha256()
    expected_digest.update(STATEMENT_DIGEST_DOMAIN)
    expected_digest.update(
        len(scenario.statement_wire).to_bytes(4, byteorder="big", signed=False)
    )
    expected_digest.update(scenario.statement_wire)
    assert result.statement_digest == expected_digest.digest()
    assert result.approval_id.hex() == vector["approval_id_hex"]
    assert result.observable_commitment.hex() == vector["observable_commitment_hex"]
    assert result.consumed_at == vector["current_time"]
    assert result.scope_platform == "linux"
    assert result.scope_format == "elf"
    assert type(result.observables) is tuple
    assert result.observables == (("api_import", "mmap"),)
    assert {field.name for field in dataclasses.fields(result)} == {
        "statement_digest",
        "approval_id",
        "observable_commitment",
        "consumed_at",
        "scope_platform",
        "scope_format",
        "observables",
    }
    assert _consumption_count(_ledger_path(scenario)) == 1
    assert _high_water(_ledger_path(scenario)) == vector["current_time"]


def test_replay_is_final_and_survives_restart(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    _promote(_service(scenario), scenario)

    with pytest.raises(
        ThreatHintV2PromotionReplayError,
        match=r"^threat-hint v2 promotion replay$",
    ):
        _promote(_service(scenario), scenario)
    assert _consumption_count(_ledger_path(scenario)) == 1


@pytest.mark.parametrize(
    "text",
    [
        _VALID_POLICY_TEXT.replace("schema_version = 1", "schema_version = 2"),
        _VALID_POLICY_TEXT.replace("schema_version = 1", 'schema_version = "1"'),
        _VALID_POLICY_TEXT.replace(
            "schema_version = 1", "schema_version = 1\nunexpected = true"
        ),
        _VALID_POLICY_TEXT.replace("max_observables = 16\n", ""),
        _VALID_POLICY_TEXT.replace('scope_platform = "linux"', "scope_platform = 10"),
        _VALID_POLICY_TEXT.replace(
            'scope_platform = "linux"', 'scope_platform = "solaris"'
        ),
        _VALID_POLICY_TEXT.replace('scope_format = "elf"', "scope_format = true"),
        _VALID_POLICY_TEXT.replace('scope_format = "elf"', 'scope_format = "coff"'),
        _VALID_POLICY_TEXT.replace(
            'allowed_observable_kinds = ["api_import", "file_sha256"]',
            "allowed_observable_kinds = []",
        ),
        _VALID_POLICY_TEXT.replace(
            'allowed_observable_kinds = ["api_import", "file_sha256"]',
            'allowed_observable_kinds = ["api_import", "api_import"]',
        ),
        _VALID_POLICY_TEXT.replace(
            'allowed_observable_kinds = ["api_import", "file_sha256"]',
            'allowed_observable_kinds = ["registry_key"]',
        ),
        _VALID_POLICY_TEXT.replace(
            'allowed_observable_kinds = ["api_import", "file_sha256"]',
            'allowed_observable_kinds = "api_import"',
        ),
        _VALID_POLICY_TEXT.replace(
            'allowed_observable_kinds = ["api_import", "file_sha256"]',
            "allowed_observable_kinds = [1]",
        ),
        _VALID_POLICY_TEXT.replace("max_observables = 16", "max_observables = 0"),
        _VALID_POLICY_TEXT.replace("max_observables = 16", "max_observables = 17"),
        _VALID_POLICY_TEXT.replace("max_observables = 16", "max_observables = true"),
        _VALID_POLICY_TEXT.replace("max_observables = 16", 'max_observables = "2"'),
    ],
)
def test_policy_rejects_non_exact_schema_and_malformed_values(
    tmp_path: Path, text: str
) -> None:
    scenario = _Scenario(tmp_path)
    config, consumption_policy = _acceptance_paths(scenario)
    promotion_policy = _write_promotion_policy(
        scenario.directory, raw=text.encode("ascii")
    )

    with pytest.raises(
        ThreatHintV2PromotionUnavailableError,
        match=r"^threat-hint v2 promotion unavailable$",
    ):
        ThreatHintV2PromotionService(
            config, scenario.policy_path, consumption_policy, promotion_policy
        )
    assert not _ledger_path(scenario).exists()


def test_policy_requires_owner_only_regular_absolute_file(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    config, consumption_policy = _acceptance_paths(scenario)

    def construct(policy_path: Path) -> None:
        ThreatHintV2PromotionService(
            config, scenario.policy_path, consumption_policy, policy_path
        )

    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        construct(Path("relative-policy.toml"))
    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        construct(str(scenario.directory))  # type: ignore[arg-type]
    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        construct(Path(f"{scenario.directory}/policy-\x00.toml"))
    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        construct(scenario.directory / "missing.toml")
    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        construct(scenario.directory)

    target = _write_promotion_policy(scenario.directory, name="target.toml")
    link = scenario.directory / "policy-link.toml"
    link.symlink_to(target)
    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        construct(link)

    mode_path = _write_promotion_policy(scenario.directory, name="mode.toml")
    mode_path.chmod(0o640)
    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        construct(mode_path)

    empty_path = _write_owner_file(scenario.directory / "empty.toml", b"")
    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        construct(empty_path)

    oversized_path = _write_owner_file(
        scenario.directory / "oversized.toml",
        b"#" * (MAX_PROMOTION_POLICY_BYTES + 1),
    )
    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        construct(oversized_path)

    non_ascii_path = _write_owner_file(
        scenario.directory / "non-ascii.toml", b"schema_version = 1\n# \xff\n"
    )
    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        construct(non_ascii_path)

    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    shared.chmod(0o755)
    shared_policy = _write_promotion_policy(shared)
    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        construct(shared_policy)

    real_parent = scenario.directory / "real-parent"
    real_parent.mkdir(mode=0o700)
    real_parent.chmod(0o700)
    ancestor_policy = _write_promotion_policy(real_parent)
    linked_parent = scenario.directory / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        construct(linked_parent / ancestor_policy.name)
    assert not _ledger_path(scenario).exists()


@pytest.mark.parametrize("replacement_kind", ("symlink", "regular"))
def test_policy_swap_between_check_and_open_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replacement_kind: str
) -> None:
    scenario = _Scenario(tmp_path)
    config, consumption_policy = _acceptance_paths(scenario)
    promotion_policy = _write_promotion_policy(scenario.directory)
    replacement = _write_promotion_policy(
        scenario.directory, name="replacement-policy.toml"
    )
    original_open = os.open
    swapped = False

    def swap_then_open(path: Path, flags: int) -> int:
        nonlocal swapped
        if Path(path) == promotion_policy and not swapped:
            swapped = True
            promotion_policy.unlink()
            if replacement_kind == "symlink":
                promotion_policy.symlink_to(replacement)
            else:
                os.replace(replacement, promotion_policy)
        return original_open(path, flags)

    monkeypatch.setattr(promotion_module.os, "open", swap_then_open)
    with pytest.raises(
        ThreatHintV2PromotionUnavailableError,
        match=r"^threat-hint v2 promotion unavailable$",
    ):
        ThreatHintV2PromotionService(
            config, scenario.policy_path, consumption_policy, promotion_policy
        )
    assert swapped
    assert not _ledger_path(scenario).exists()


def test_construction_trusted_material_mismatch_is_unavailable(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    config, consumption_policy = _acceptance_paths(scenario, key_hex="55" * 32)
    promotion_policy = _write_promotion_policy(scenario.directory)

    with pytest.raises(
        ThreatHintV2PromotionUnavailableError,
        match=r"^threat-hint v2 promotion unavailable$",
    ):
        ThreatHintV2PromotionService(
            config, scenario.policy_path, consumption_policy, promotion_policy
        )
    assert not _ledger_path(scenario).exists()


@pytest.mark.parametrize(
    "case",
    [
        {"policy": {"platform": "windows"}},
        {"policy": {"platform": "macos"}},
        {"policy": {"artifact_format": "pe"}},
        {"policy": {"kinds": ("file_sha256",)}},
        {
            "policy": {
                "kinds": ("api_import", "file_sha256"),
                "max_observables": 1,
            },
            "bundle": _TWO_OBSERVABLE_BUNDLE,
        },
        {"policy": {}, "bundle": _NONCANONICAL_BUNDLE},
        {"policy": {}, "bundle": b'{"schema_version":1}'},
        {"policy": {}, "bundle": _PUBLIC_AUTO_BUNDLE},
    ],
)
def test_restricted_candidates_fail_before_verifier_and_ledger(
    tmp_path: Path, case: dict
) -> None:
    scenario = _Scenario(tmp_path)
    marker = scenario.directory / "verifier-ran"
    service = _service(scenario, _marker_body(marker), **case["policy"])

    with pytest.raises(
        ThreatHintV2PromotionError, match=r"^invalid threat-hint v2 promotion$"
    ):
        _promote(
            service,
            scenario,
            bundle_wire=case.get("bundle", scenario.bundle_wire),
        )
    assert not marker.exists()
    assert _consumption_count(_ledger_path(scenario)) == 0
    assert _high_water(_ledger_path(scenario)) == 0


def test_failed_promotion_leaves_approval_consumable(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    marker = scenario.directory / "verifier-ran"
    service = _service(
        scenario,
        _marker_body(marker),
        kinds=("api_import", "file_sha256"),
        max_observables=1,
    )

    for bad_bundle in (
        b'{"schema_version":1}',
        _NONCANONICAL_BUNDLE,
        _PUBLIC_AUTO_BUNDLE,
        _TWO_OBSERVABLE_BUNDLE,
    ):
        with pytest.raises(
            ThreatHintV2PromotionError, match=r"^invalid threat-hint v2 promotion$"
        ):
            _promote(service, scenario, bundle_wire=bad_bundle)
    assert not marker.exists()
    assert _consumption_count(_ledger_path(scenario)) == 0
    assert _high_water(_ledger_path(scenario)) == 0

    result = _promote(service, scenario)
    assert result.observables == (("api_import", "mmap"),)
    assert _consumption_count(_ledger_path(scenario)) == 1
    assert _high_water(_ledger_path(scenario)) == scenario.vector["current_time"]


@pytest.mark.parametrize(
    "changes",
    [
        {"envelope_wire": "text"},
        {"envelope_wire": bytearray(b"aa")},
        {"envelope_wire": _BytesSubclass(b"aa")},
        {"bundle_wire": bytearray(b"aa")},
        {"bundle_wire": _BytesSubclass(b"aa")},
        {"approval_wire": None},
        {"approval_wire": True},
        {"approval_wire": _BytesSubclass(b"aa")},
        {"report_nonce": b"\x11" * 31},
        {"report_nonce": "aa" * 32},
        {"report_nonce": None},
        {"report_nonce": _BytesSubclass(b"\x11" * 32)},
        {"current_time": 0},
        {"current_time": -1},
        {"current_time": True},
        {"current_time": _IntSubclass(1)},
        {"current_time": 1 << 64},
        {"current_time": "1700000300"},
    ],
)
def test_raw_only_inputs_fail_before_verifier_and_ledger(
    tmp_path: Path, changes: dict
) -> None:
    scenario = _Scenario(tmp_path)
    marker = scenario.directory / "verifier-ran"
    service = _service(scenario, _marker_body(marker))

    with pytest.raises(
        ThreatHintV2PromotionError, match=r"^invalid threat-hint v2 promotion$"
    ):
        _promote(service, scenario, **changes)
    assert not marker.exists()
    assert _consumption_count(_ledger_path(scenario)) == 0
    assert _high_water(_ledger_path(scenario)) == 0


def test_acceptance_candidate_failure_maps_to_invalid(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    service = _service(scenario)

    with pytest.raises(
        ThreatHintV2PromotionError, match=r"^invalid threat-hint v2 promotion$"
    ):
        _promote(service, scenario, report_nonce=b"\x44" * 32)
    assert _consumption_count(_ledger_path(scenario)) == 0
    assert _high_water(_ledger_path(scenario)) == 0

    result = _promote(service, scenario)
    assert result.observables == (("api_import", "mmap"),)
    assert _consumption_count(_ledger_path(scenario)) == 1
    assert _high_water(_ledger_path(scenario)) == scenario.vector["current_time"]


def test_public_api_accepts_only_raw_wires_and_owner_paths() -> None:
    constructor = inspect.signature(ThreatHintV2PromotionService)
    assert set(constructor.parameters) == {
        "config_path",
        "preflight_policy_path",
        "consumption_policy_path",
        "promotion_policy_path",
    }
    call = inspect.signature(ThreatHintV2PromotionService.promote)
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
        "observables",
    ):
        assert forbidden not in call.parameters
    source = inspect.getsource(promotion_module)
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith(("import ", "from ")):
            lowered = stripped.lower()
            for forbidden in (
                "analyzer",
                "llm",
                "yara",
                "outbox",
                "transport",
                "sqlite3",
                "subprocess",
                "wallet",
                "chain",
            ):
                assert forbidden not in lowered
    assert "shell=True" not in source


def test_errors_are_stable_and_redacted(tmp_path: Path) -> None:
    assert str(ThreatHintV2PromotionError()) == "invalid threat-hint v2 promotion"
    assert (
        str(ThreatHintV2PromotionUnavailableError())
        == "threat-hint v2 promotion unavailable"
    )
    assert str(ThreatHintV2PromotionReplayError()) == "threat-hint v2 promotion replay"
    assert str(ThreatHintV2PromotionBusyError()) == "threat-hint v2 promotion busy"
    for subclass in (
        ThreatHintV2PromotionUnavailableError,
        ThreatHintV2PromotionReplayError,
        ThreatHintV2PromotionBusyError,
    ):
        assert issubclass(subclass, ThreatHintV2PromotionError)

    marker = "secret$promotion-marker"
    scenario = _Scenario(tmp_path)
    config, consumption_policy = _acceptance_paths(scenario)
    marked_policy = _write_owner_file(
        scenario.directory / "marked-policy.toml", marker.encode("ascii")
    )
    with pytest.raises(ThreatHintV2PromotionUnavailableError) as policy_error:
        ThreatHintV2PromotionService(
            config, scenario.policy_path, consumption_policy, marked_policy
        )
    assert str(policy_error.value) == "threat-hint v2 promotion unavailable"
    assert marker not in str(policy_error.value)

    service = _service(scenario, platform="windows")
    with pytest.raises(ThreatHintV2PromotionError) as promote_error:
        _promote(service, scenario)
    message = str(promote_error.value)
    assert message == "invalid threat-hint v2 promotion"
    for sensitive in (
        scenario.vector["trusted_approver_xonly_public_key_hex"],
        scenario.vector["trusted_recipient_scope_hex"],
        scenario.vector["report_nonce_hex"],
        scenario.anchor_hex,
        "windows",
    ):
        assert sensitive not in message


def test_result_is_restricted_data_and_not_serializable(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    result = _promote(_service(scenario), scenario)

    with pytest.raises(TypeError):
        ThreatHintV2PromotionResult()
    with pytest.raises(TypeError):
        dataclasses.replace(result)
    with pytest.raises(TypeError):
        pickle.dumps(result)
    forged = object.__new__(ThreatHintV2PromotionResult)
    with pytest.raises(AttributeError):
        _ = forged.statement_digest
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.consumed_at = 0  # type: ignore[misc]

    rendered = repr(result)
    for sensitive in (
        scenario.vector["approval_id_hex"],
        scenario.vector["observable_commitment_hex"],
        scenario.anchor_hex,
        "mmap",
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
        "receipt",
        "approver_xonly_public_key",
        "recipient_scope",
        "report_nonce",
        "raw_manifest_sha256_hex",
        "envelope_sha256_hex",
        "verifier_executable_sha256_hex",
        "network_id",
        "ledger_path",
    ):
        assert not hasattr(result, forbidden)


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
    result: list[ThreatHintV2PromotionResult] = []
    errors: list[BaseException] = []

    def first_call() -> None:
        try:
            result.append(_promote(service, scenario))
        except BaseException as error:  # pragma: no cover - assertion captures
            errors.append(error)

    worker = threading.Thread(target=first_call)
    worker.start()
    deadline = time.monotonic() + 15
    while not started.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert started.exists()

    with pytest.raises(
        ThreatHintV2PromotionBusyError,
        match=r"^threat-hint v2 promotion busy$",
    ):
        _promote(service, scenario)
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
            ThreatHintV2PromotionBusyError,
            match=r"^threat-hint v2 promotion busy$",
        ):
            _promote(service, scenario)
    finally:
        lock.rollback()
        lock.close()

    assert _consumption_count(ledger_path) == 0
    assert _high_water(ledger_path) == 0
    _promote(service, scenario)
    assert _consumption_count(ledger_path) == 1


def test_concurrent_duplicate_has_exactly_one_winner(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    service = _service(scenario)

    def attempt() -> str:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                _promote(service, scenario)
                return "consumed"
            except ThreatHintV2PromotionReplayError:
                return "replay"
            except ThreatHintV2PromotionBusyError:
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
