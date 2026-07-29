"""Integration tests for governed ThreatHint-v2 promotion and consumption."""

# Tests intentionally inspect the local ledger and reuse candidate fixtures.
# pylint: disable=missing-function-docstring,too-many-locals

from __future__ import annotations

import hashlib
import os
import shlex
import sqlite3
from pathlib import Path
from typing import Iterable

import pytest
from coincurve import PrivateKey, PublicKeyXOnly

from jaeger.observable_approval_consumption import (
    ObservableApprovalConsumptionError,
    ObservableApprovalConsumptionService,
)
from jaeger.threat_hint_v2_promotion import (
    ThreatHintV2PromotionBusyError,
    ThreatHintV2PromotionError,
    ThreatHintV2PromotionReplayError,
    ThreatHintV2PromotionService,
    ThreatHintV2PromotionUnavailableError,
)
from jaeger.threat_observable import MAX_OBSERVABLES
from tests.test_threat_hint_v2_acceptance import (
    _consumption_count,
    _high_water,
    _ledger_path,
    _write_consumption_policy,
)
from tests.test_threat_hint_v2_preflight import (
    _Scenario,
    _signed_approval,
    _write_policy as _write_preflight_policy,
)
from tests.test_threat_hint_v2_promotion import (
    _promote,
    _write_promotion_policy,
)
from tests.test_threat_hint_v2_verified_preflight import (
    _write_config,
    _write_owner_file,
    _write_verifier,
)

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="governed promotion requires POSIX controls"
)

_ALLOW_TOKEN = {
    "file_sha256": "allow_local_analysis_corpus_matchable_v1",
    "api_import": "allow_local_analysis_software_fingerprint_v1",
    "byte_pattern": "allow_local_analysis_content_derived_v1",
}
_ALL_KINDS = ("api_import", "file_sha256", "byte_pattern")


def _write_governance_policy(
    scenario: _Scenario,
    *,
    epoch: int = 1,
    key_hex: str | None = None,
    allowed_kinds: Iterable[str] = _ALL_KINDS,
    not_before: int = 1_799_999_999,
    not_after: int = 1_800_000_601,
    name: str = "governance-policy.toml",
) -> Path:
    allowed = frozenset(allowed_kinds)
    decisions = [
        f'{kind} = "{_ALLOW_TOKEN[kind] if kind in allowed else "deny_v1"}"'
        for kind in ("file_sha256", "api_import", "byte_pattern")
    ]
    wire = "\n".join(
        (
            "schema_version = 1",
            f'network_id = "{scenario.vector["network_id"]}"',
            "approver_xonly_public_key = "
            f'"{key_hex or scenario.vector["trusted_approver_xonly_public_key_hex"]}"',
            "recipient_scope = " f'"{scenario.vector["trusted_recipient_scope_hex"]}"',
            f"authority_epoch = {epoch}",
            f"authority_not_before = {not_before}",
            f"authority_not_after = {not_after}",
            'recipient_purpose = "guardian_local_analysis_v1"',
            'recipient_boundary = "same_guardian_owner_v1"',
            'external_disclosure = "deny_v1"',
            "",
            "[observable_decisions]",
            *decisions,
            "",
        )
    ).encode("ascii")
    return _write_owner_file(scenario.directory / name, wire)


def _write_retention_policy(
    scenario: _Scenario,
    *,
    key_hex: str | None = None,
    kinds: Iterable[str] = _ALL_KINDS,
    max_pending_records: int = 1000,
    max_retention_seconds: int = 86400,
    name: str = "retention-policy.toml",
) -> Path:
    kinds_text = ", ".join(f'"{kind}"' for kind in kinds)
    wire = "\n".join(
        (
            "schema_version = 1",
            f'network_id = "{scenario.vector["network_id"]}"',
            "approver_xonly_public_key = "
            f'"{key_hex or scenario.vector["trusted_approver_xonly_public_key_hex"]}"',
            "recipient_scope = " f'"{scenario.vector["trusted_recipient_scope_hex"]}"',
            'retention_purpose = "local_recoverable_analysis_queue_v1"',
            'payload_form = "canonical_observable_bundle_v1"',
            f"durable_observable_kinds = [{kinds_text}]",
            f"max_pending_records = {max_pending_records}",
            f"max_retention_seconds = {max_retention_seconds}",
            "",
        )
    ).encode("ascii")
    return _write_owner_file(scenario.directory / name, wire)


def _governed_service(
    scenario: _Scenario,
    *,
    epoch: int = 1,
    key_hex: str | None = None,
    kinds: Iterable[str] = _ALL_KINDS,
    verifier_body: str = "/bin/cat >/dev/null\nexit 0",
    authority_not_before: int = 1_799_999_999,
    authority_not_after: int = 1_800_000_601,
    max_observables: int = MAX_OBSERVABLES,
    retention_max_pending_records: int = 1000,
    retention_max_retention_seconds: int = 86400,
) -> ThreatHintV2PromotionService:
    manifest = _write_owner_file(
        scenario.directory / "relation-manifest-v2.json",
        scenario.manifest_wire,
    )
    verifier = _write_verifier(scenario.directory, verifier_body)
    config = _write_config(scenario.directory, verifier, manifest)
    consumption = _write_consumption_policy(
        scenario.directory,
        scenario.vector,
        key_hex=key_hex,
    )
    promotion = _write_promotion_policy(
        scenario.directory,
        kinds=kinds,
        max_observables=max_observables,
    )
    governance = _write_governance_policy(
        scenario,
        epoch=epoch,
        key_hex=key_hex,
        allowed_kinds=kinds,
        not_before=authority_not_before,
        not_after=authority_not_after,
    )
    retention = _write_retention_policy(
        scenario,
        key_hex=key_hex,
        kinds=kinds,
        max_pending_records=retention_max_pending_records,
        max_retention_seconds=retention_max_retention_seconds,
    )
    return ThreatHintV2PromotionService.from_governed_policies(
        config,
        scenario.policy_path,
        consumption,
        promotion,
        governance,
        retention,
    )


def _authority_state(path: Path) -> tuple | None:
    with sqlite3.connect(path) as connection:
        return connection.execute("""
            SELECT authority_epoch, governance_policy_sha256,
                   retention_policy_sha256, promotion_policy_sha256,
                   network_id, approver_xonly_public_key, recipient_scope,
                   authority_not_before, authority_not_after
            FROM authority_state WHERE singleton = 1
            """).fetchone()


def _schema_version(path: Path) -> int:
    with sqlite3.connect(path) as connection:
        return connection.execute("PRAGMA user_version").fetchone()[0]


def test_first_valid_governed_promotion_pins_every_state_atomically(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    service = _governed_service(scenario)
    ledger = _ledger_path(scenario)

    assert _schema_version(ledger) == 4
    assert _authority_state(ledger) is None

    result = _promote(service, scenario)

    state = _authority_state(ledger)
    assert state is not None
    assert state[0] == 1
    assert len(state[1]) == len(state[2]) == len(state[3]) == 32
    assert state[4] == scenario.vector["network_id"]
    assert state[5] == bytes.fromhex(
        scenario.vector["trusted_approver_xonly_public_key_hex"]
    )
    assert state[6] == bytes.fromhex(scenario.vector["trusted_recipient_scope_hex"])
    assert result.approval_id.hex() == scenario.vector["approval_id_hex"]
    assert _consumption_count(ledger) == 1
    assert _high_water(ledger) == scenario.current_time


@pytest.mark.parametrize(
    ("promotion_kinds", "retention_kinds"),
    [
        (("api_import",), _ALL_KINDS),
        (_ALL_KINDS, ("api_import",)),
    ],
)
def test_kind_snapshot_mismatch_fails_before_ledger_creation(
    tmp_path: Path,
    promotion_kinds: tuple[str, ...],
    retention_kinds: tuple[str, ...],
) -> None:
    scenario = _Scenario(tmp_path)
    manifest = _write_owner_file(
        scenario.directory / "relation-manifest-v2.json",
        scenario.manifest_wire,
    )
    verifier = _write_verifier(scenario.directory, "/bin/cat >/dev/null\nexit 0")
    config = _write_config(scenario.directory, verifier, manifest)
    consumption = _write_consumption_policy(scenario.directory, scenario.vector)
    promotion = _write_promotion_policy(
        scenario.directory,
        kinds=promotion_kinds,
    )
    governance = _write_governance_policy(
        scenario,
        allowed_kinds=_ALL_KINDS,
    )
    retention = _write_retention_policy(scenario, kinds=retention_kinds)

    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        ThreatHintV2PromotionService.from_governed_policies(
            config,
            scenario.policy_path,
            consumption,
            promotion,
            governance,
            retention,
        )
    assert not _ledger_path(scenario).exists()


def test_authority_window_rejection_never_invokes_verifier_or_pins_state(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    marker = scenario.directory / "verifier-ran"
    body = (
        f"printf 'ran\\n' >> {shlex.quote(str(marker))}\n" "/bin/cat >/dev/null\nexit 0"
    )
    service = _governed_service(
        scenario,
        verifier_body=body,
        authority_not_before=scenario.vector["not_before"] + 1,
    )
    ledger = _ledger_path(scenario)

    with pytest.raises(ThreatHintV2PromotionError):
        _promote(service, scenario)
    assert not marker.exists()
    assert _authority_state(ledger) is None
    assert _consumption_count(ledger) == 0
    assert _high_water(ledger) == 0


def test_same_epoch_digest_equivocation_fails_before_verifier(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    _promote(_governed_service(scenario), scenario)
    ledger = _ledger_path(scenario)
    pinned = _authority_state(ledger)
    marker = scenario.directory / "stale-verifier-ran"
    body = (
        f"printf 'ran\\n' >> {shlex.quote(str(marker))}\n" "/bin/cat >/dev/null\nexit 0"
    )
    service = _governed_service(scenario, verifier_body=body)
    governance = _write_governance_policy(
        scenario,
        not_before=1_799_999_998,
    )
    # Reconstruct once more so the changed exact bytes are the loaded snapshot.
    manifest = scenario.directory / "relation-manifest-v2.json"
    verifier = _write_verifier(scenario.directory, body)
    config = _write_config(scenario.directory, verifier, manifest)
    service = ThreatHintV2PromotionService.from_governed_policies(
        config,
        scenario.policy_path,
        scenario.directory / "consumption-policy.toml",
        scenario.directory / "promotion-policy.toml",
        governance,
        scenario.directory / "retention-policy.toml",
    )

    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        _promote(service, scenario)
    assert not marker.exists()
    assert _authority_state(ledger) == pinned
    assert _consumption_count(ledger) == 1


def test_same_epoch_promotion_digest_equivocation_fails_before_verifier(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    _promote(_governed_service(scenario), scenario)
    ledger = _ledger_path(scenario)
    pinned = _authority_state(ledger)
    marker = scenario.directory / "promotion-equivocation-verifier-ran"
    body = (
        f"printf 'ran\\n' >> {shlex.quote(str(marker))}\n" "/bin/cat >/dev/null\nexit 0"
    )
    service = _governed_service(
        scenario,
        verifier_body=body,
        max_observables=MAX_OBSERVABLES - 1,
    )

    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        _promote(service, scenario)
    assert not marker.exists()
    assert _authority_state(ledger) == pinned
    assert _consumption_count(ledger) == 1


def test_same_epoch_retention_digest_equivocation_fails_before_verifier(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    _promote(_governed_service(scenario), scenario)
    ledger = _ledger_path(scenario)
    pinned = _authority_state(ledger)
    marker = scenario.directory / "retention-equivocation-verifier-ran"
    body = (
        f"printf 'ran\\n' >> {shlex.quote(str(marker))}\n" "/bin/cat >/dev/null\nexit 0"
    )
    service = _governed_service(
        scenario,
        verifier_body=body,
        retention_max_pending_records=999,
    )

    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        _promote(service, scenario)
    assert not marker.exists()
    assert _authority_state(ledger) == pinned
    assert _consumption_count(ledger) == 1


def test_overlapping_same_identity_epoch_advance_fails_before_verifier(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    _promote(_governed_service(scenario), scenario)
    ledger = _ledger_path(scenario)
    pinned = _authority_state(ledger)
    marker = scenario.directory / "overlap-verifier-ran"
    body = (
        f"printf 'ran\\n' >> {shlex.quote(str(marker))}\n" "/bin/cat >/dev/null\nexit 0"
    )
    service = _governed_service(scenario, epoch=2, verifier_body=body)

    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        _promote(service, scenario)
    assert not marker.exists()
    assert _authority_state(ledger) == pinned
    assert _consumption_count(ledger) == 1


def test_epoch_regression_fails_without_verifier_or_state_change(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    key = PrivateKey()
    key_hex = PublicKeyXOnly.from_secret(key.secret).format().hex()
    _write_preflight_policy(
        scenario.directory,
        scenario.vector,
        scenario.anchor_hex,
        key_hex=key_hex,
    )
    scenario.approval_wire = _signed_approval(scenario, key)
    _promote(_governed_service(scenario, epoch=2, key_hex=key_hex), scenario)
    pinned = _authority_state(_ledger_path(scenario))
    marker = scenario.directory / "rollback-verifier-ran"
    body = (
        f"printf 'ran\\n' >> {shlex.quote(str(marker))}\n" "/bin/cat >/dev/null\nexit 0"
    )
    service = _governed_service(
        scenario,
        epoch=1,
        key_hex=key_hex,
        verifier_body=body,
    )

    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        _promote(service, scenario)
    assert not marker.exists()
    assert _authority_state(_ledger_path(scenario)) == pinned
    assert _consumption_count(_ledger_path(scenario)) == 1


def test_higher_epoch_advances_only_with_success_and_preserves_replay_state(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    _promote(_governed_service(scenario), scenario)
    ledger = _ledger_path(scenario)
    first_high_water = _high_water(ledger)

    key = PrivateKey()
    key_hex = PublicKeyXOnly.from_secret(key.secret).format().hex()
    _write_preflight_policy(
        scenario.directory,
        scenario.vector,
        scenario.anchor_hex,
        key_hex=key_hex,
    )
    scenario.approval_wire = _signed_approval(scenario, key)
    service = _governed_service(scenario, epoch=2, key_hex=key_hex)

    assert _authority_state(ledger)[0] == 1
    _promote(service, scenario)

    assert _authority_state(ledger)[0] == 2
    assert _consumption_count(ledger) == 2
    assert _high_water(ledger) == first_high_water


def test_nonoverlapping_same_identity_epoch_advance_succeeds(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    key = PrivateKey()
    key_hex = PublicKeyXOnly.from_secret(key.secret).format().hex()
    _write_preflight_policy(
        scenario.directory,
        scenario.vector,
        scenario.anchor_hex,
        key_hex=key_hex,
    )
    scenario.approval_wire = _signed_approval(scenario, key)
    _promote(_governed_service(scenario, key_hex=key_hex), scenario)
    ledger = _ledger_path(scenario)

    next_not_before = 1_800_000_602
    scenario.vector["not_before"] = next_not_before
    scenario.vector["expires_at"] = next_not_before + 300
    scenario.vector["approval_nonce_hex"] = "ab" * 32
    scenario.current_time = next_not_before + 1
    scenario.approval_wire = _signed_approval(scenario, key)
    service = _governed_service(
        scenario,
        epoch=2,
        key_hex=key_hex,
        authority_not_before=next_not_before,
        authority_not_after=next_not_before + 400,
    )

    _promote(service, scenario)

    state = _authority_state(ledger)
    assert state is not None
    assert state[0] == 2
    assert state[7:] == (next_not_before, next_not_before + 400)
    assert _consumption_count(ledger) == 2
    assert _high_water(ledger) == scenario.current_time


def test_failed_insert_rolls_back_epoch_digest_and_high_water(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    _promote(_governed_service(scenario), scenario)
    ledger = _ledger_path(scenario)
    pinned = _authority_state(ledger)
    high_water = _high_water(ledger)

    key = PrivateKey()
    key_hex = PublicKeyXOnly.from_secret(key.secret).format().hex()
    _write_preflight_policy(
        scenario.directory,
        scenario.vector,
        scenario.anchor_hex,
        key_hex=key_hex,
    )
    scenario.approval_wire = _signed_approval(scenario, key)
    service = _governed_service(scenario, epoch=2, key_hex=key_hex)
    with sqlite3.connect(ledger) as connection:
        connection.execute("""
            CREATE TRIGGER reject_governed_consumption
            BEFORE INSERT ON approval_consumptions
            BEGIN
                SELECT RAISE(ABORT, 'injected failure');
            END
            """)

    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        _promote(service, scenario)

    assert _authority_state(ledger) == pinned
    assert _high_water(ledger) == high_water
    assert _consumption_count(ledger) == 1


def test_v1_migration_preserves_existing_replay_and_does_not_pin_on_replay(
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
    assert _authority_state(ledger) is None
    with pytest.raises(ThreatHintV2PromotionReplayError):
        _promote(service, scenario)

    assert _authority_state(ledger) is None
    assert _consumption_count(ledger) == 1
    assert _high_water(ledger) == scenario.current_time


def test_v1_migration_rejects_preexisting_authority_table(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    ObservableApprovalConsumptionService(
        _write_consumption_policy(scenario.directory, scenario.vector)
    )
    ledger = _ledger_path(scenario)
    with sqlite3.connect(ledger) as connection:
        connection.execute("CREATE TABLE authority_state (injected INTEGER) STRICT")

    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        _governed_service(scenario)

    assert _schema_version(ledger) == 1


def test_v0_migration_rejects_preexisting_authority_table(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    ledger = _ledger_path(scenario)
    with sqlite3.connect(ledger) as connection:
        connection.execute("CREATE TABLE authority_state (injected INTEGER) STRICT")
    ledger.chmod(0o600)

    with pytest.raises(ThreatHintV2PromotionUnavailableError):
        _governed_service(scenario)

    assert _schema_version(ledger) == 0


def test_migrated_ledger_refuses_legacy_downgrade(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    _governed_service(scenario)
    with pytest.raises(ObservableApprovalConsumptionError):
        ObservableApprovalConsumptionService(
            scenario.directory / "consumption-policy.toml"
        )


def test_persisted_policy_digests_are_exact_owner_file_hashes(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    _promote(_governed_service(scenario), scenario)
    state = _authority_state(_ledger_path(scenario))
    assert state is not None
    assert (
        state[1]
        == hashlib.sha256(
            (scenario.directory / "governance-policy.toml").read_bytes()
        ).digest()
    )
    assert (
        state[2]
        == hashlib.sha256(
            (scenario.directory / "retention-policy.toml").read_bytes()
        ).digest()
    )
    assert (
        state[3]
        == hashlib.sha256(
            (scenario.directory / "promotion-policy.toml").read_bytes()
        ).digest()
    )


def test_governed_ledger_lock_is_retryable_without_verifier_or_pin(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    marker = scenario.directory / "locked-verifier-ran"
    service = _governed_service(
        scenario,
        verifier_body=(
            f"printf 'ran\\n' >> {shlex.quote(str(marker))}\n"
            "/bin/cat >/dev/null\nexit 0"
        ),
    )
    ledger = _ledger_path(scenario)
    lock = sqlite3.connect(ledger, isolation_level=None)
    lock.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(ThreatHintV2PromotionBusyError):
            _promote(service, scenario)
    finally:
        lock.rollback()
        lock.close()

    assert not marker.exists()
    assert _authority_state(ledger) is None
    _promote(service, scenario)
    assert marker.exists()
    assert _consumption_count(ledger) == 1
