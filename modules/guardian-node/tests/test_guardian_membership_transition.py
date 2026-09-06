"""Tests for owner-local signed Guardian membership transitions."""

# Test helpers intentionally inspect durable state and use test-only keys.
# pylint: disable=missing-function-docstring,protected-access,too-many-arguments
# pylint: disable=too-many-positional-arguments

from __future__ import annotations

import hashlib
import json
import os
import pickle
import sqlite3
import threading
from pathlib import Path

import pytest
from coincurve import PrivateKey

import jaeger.guardian_membership_transition as transition_module
from jaeger.guardian_membership_source import MEMBERSHIP_SOURCE_PROTOCOL_ID
from jaeger.guardian_membership_transition import (
    AUTHORITY_ROTATION_AUTH_DIGEST_DOMAIN,
    AUTHORITY_ROTATION_POSSESSION_DIGEST_DOMAIN,
    AUTHORITY_ROTATION_PROTOCOL_ID,
    MEMBERSHIP_TRANSITION_DIGEST_DOMAIN,
    MEMBERSHIP_TRANSITION_PROTOCOL_ID,
    GuardianAuthorityRotationBusyError,
    GuardianAuthorityRotationError,
    GuardianAuthorityRotationReceipt,
    GuardianAuthorityRotationReplayError,
    GuardianMembershipAuthority,
    GuardianMembershipTransitionBusyError,
    GuardianMembershipTransitionError,
    GuardianMembershipTransitionReplayError,
)

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="membership authority requires POSIX file controls"
)

_NETWORK = "testnet-10"
_MODEL_HASH = hashlib.sha256(b"membership-transition-model").hexdigest()
_NOW = 1_800_000_000_000


def _members(offset: int = 0) -> list[dict[str, object]]:
    result = []
    for index in range(5):
        key = PrivateKey((offset + index + 1).to_bytes(32, "big"))
        result.append(
            {
                "guardian_id": hashlib.sha256(
                    f"transition-guardian-{offset + index}".encode("ascii")
                ).hexdigest(),
                "xonly_public_key": key.public_key_xonly.format().hex(),
                "model_tier": "8b",
                "model_artifact_sha256": _MODEL_HASH,
            }
        )
    return sorted(result, key=lambda member: member["guardian_id"])


def _source_bytes(epoch: int, *, offset: int = 0, network: str = _NETWORK) -> bytes:
    return json.dumps(
        {
            "schema_version": 1,
            "protocol_id": MEMBERSHIP_SOURCE_PROTOCOL_ID,
            "network_id": network,
            "epoch": epoch,
            "members": _members(offset),
        },
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _write_private(path: Path, contents: bytes) -> Path:
    path.parent.chmod(0o700)
    path.write_bytes(contents)
    path.chmod(0o600)
    return path


def _write_policy(
    directory: Path,
    authority_key: PrivateKey,
    bootstrap_path: Path,
    ledger_path: Path,
    *,
    network: str = _NETWORK,
    bootstrap_epoch: int = 0,
    bootstrap_digest: str | None = None,
    suffix: str = "",
) -> Path:
    digest = bootstrap_digest or hashlib.sha256(bootstrap_path.read_bytes()).hexdigest()
    policy = "\n".join(
        (
            "schema_version = 1",
            f'network_id = "{network}"',
            'authority_xonly_public_key = "'
            + authority_key.public_key_xonly.format().hex()
            + '"',
            f"bootstrap_epoch = {bootstrap_epoch}",
            f'bootstrap_membership_source_sha256 = "{digest}"',
            f'bootstrap_membership_source_path = "{bootstrap_path}"',
            f'ledger_path = "{ledger_path}"',
            "",
        )
    ).encode("ascii")
    return _write_private(directory / f"membership-authority{suffix}.toml", policy)


def _setup(directory: Path):
    directory.chmod(0o700)
    authority_key = PrivateKey((901).to_bytes(32, "big"))
    bootstrap = _write_private(directory / "membership-0.json", _source_bytes(0))
    ledger = directory / "membership.sqlite3"
    policy = _write_policy(directory, authority_key, bootstrap, ledger)
    return authority_key, bootstrap, ledger, policy


def _next_source(directory: Path, epoch: int, *, offset: int | None = None) -> Path:
    return _write_private(
        directory / f"membership-{epoch}.json",
        _source_bytes(epoch, offset=epoch * 10 if offset is None else offset),
    )


def _wire(
    key: PrivateKey,
    previous_epoch: int,
    previous_digest: str,
    next_epoch: int,
    next_digest: str,
    *,
    nonce: str | None = None,
    network: str = _NETWORK,
    not_before_ms: int = _NOW - 1_000,
    not_after_ms: int = _NOW + 10_000,
    sign_with: PrivateKey | None = None,
) -> bytes:
    unsigned = {
        "schema_version": 1,
        "protocol_id": MEMBERSHIP_TRANSITION_PROTOCOL_ID,
        "network_id": network,
        "previous_epoch": previous_epoch,
        "previous_membership_source_sha256": previous_digest,
        "next_epoch": next_epoch,
        "next_membership_source_sha256": next_digest,
        "not_before_ms": not_before_ms,
        "not_after_ms": not_after_ms,
        "nonce": nonce or hashlib.sha256(f"nonce-{next_epoch}".encode()).hexdigest(),
    }
    unsigned_wire = json.dumps(
        unsigned, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    digest = hashlib.sha256(
        MEMBERSHIP_TRANSITION_DIGEST_DOMAIN
        + len(unsigned_wire).to_bytes(4, "big")
        + unsigned_wire
    ).digest()
    document = {
        **unsigned,
        "payload_digest": digest.hex(),
        "signature": (sign_with or key)
        .sign_schnorr(digest, aux_randomness=b"\0" * 32)
        .hex(),
    }
    return json.dumps(document, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def _apply(
    authority: GuardianMembershipAuthority,
    key: PrivateKey,
    previous: Path,
    next_source: Path,
    previous_epoch: int,
    next_epoch: int,
    **wire_options,
):
    wire = _wire(
        key,
        previous_epoch,
        hashlib.sha256(previous.read_bytes()).hexdigest(),
        next_epoch,
        hashlib.sha256(next_source.read_bytes()).hexdigest(),
        **wire_options,
    )
    return authority.apply_transition(wire, next_source, _NOW), wire


def _digest(domain: bytes, wire: bytes) -> bytes:
    return hashlib.sha256(domain + len(wire).to_bytes(4, "big") + wire).digest()


def _rotation_wire(
    previous_key: PrivateKey,
    next_key: PrivateKey,
    membership_source: Path,
    *,
    previous_authority_epoch: int = 0,
    next_authority_epoch: int = 1,
    membership_epoch: int = 0,
    nonce: str | None = None,
    network: str = _NETWORK,
    not_before_ms: int = _NOW - 1_000,
    not_after_ms: int = _NOW + 10_000,
    authorize_with: PrivateKey | None = None,
    prove_with: PrivateKey | None = None,
    possession_signs_authorization: bool = False,
) -> bytes:
    unsigned = {
        "schema_version": 1,
        "protocol_id": AUTHORITY_ROTATION_PROTOCOL_ID,
        "network_id": network,
        "previous_authority_epoch": previous_authority_epoch,
        "previous_authority_xonly_public_key": previous_key.public_key_xonly.format().hex(),
        "next_authority_epoch": next_authority_epoch,
        "next_authority_xonly_public_key": next_key.public_key_xonly.format().hex(),
        "membership_epoch": membership_epoch,
        "membership_source_sha256": hashlib.sha256(
            membership_source.read_bytes()
        ).hexdigest(),
        "not_before_ms": not_before_ms,
        "not_after_ms": not_after_ms,
        "nonce": nonce
        or hashlib.sha256(
            f"authority-rotation-{next_authority_epoch}".encode("ascii")
        ).hexdigest(),
    }
    authorization_wire = json.dumps(
        unsigned, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    possession = {
        name: unsigned[name]
        for name in (
            "schema_version",
            "protocol_id",
            "network_id",
            "previous_authority_epoch",
            "next_authority_epoch",
            "next_authority_xonly_public_key",
            "membership_epoch",
            "membership_source_sha256",
            "not_before_ms",
            "not_after_ms",
            "nonce",
        )
    }
    possession_wire = json.dumps(
        possession, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    authorization_digest = _digest(
        AUTHORITY_ROTATION_AUTH_DIGEST_DOMAIN, authorization_wire
    )
    possession_digest = _digest(
        AUTHORITY_ROTATION_POSSESSION_DIGEST_DOMAIN, possession_wire
    )
    document = {
        **unsigned,
        "authorization_payload_digest": authorization_digest.hex(),
        "possession_payload_digest": possession_digest.hex(),
        "authorization_signature": (authorize_with or previous_key)
        .sign_schnorr(authorization_digest, aux_randomness=b"\0" * 32)
        .hex(),
        "possession_signature": (prove_with or next_key)
        .sign_schnorr(
            (
                authorization_digest
                if possession_signs_authorization
                else possession_digest
            ),
            aux_randomness=b"\0" * 32,
        )
        .hex(),
    }
    return json.dumps(document, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def _downgrade_fixture_to_v1(ledger: Path) -> None:
    with sqlite3.connect(ledger) as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DROP TABLE authority_rotations")
        connection.execute("DROP TABLE authority_key_history")
        connection.execute("DROP TABLE current_authority")
        connection.execute(
            "ALTER TABLE membership_transitions RENAME TO transitions_v2"
        )
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
                    CHECK(length(transition_wire) >= 1
                        AND length(transition_wire) <= 2048)
            ) STRICT
            """)
        connection.execute("""
            INSERT INTO membership_transitions
            SELECT transition_id, nonce, previous_epoch,
                previous_membership_source_sha256, next_epoch,
                next_membership_source_sha256, not_before_ms, not_after_ms,
                applied_at_ms, transition_wire
            FROM transitions_v2
            """)
        connection.execute("DROP TABLE transitions_v2")
        connection.execute("PRAGMA user_version = 1")
        connection.commit()


def test_bootstrap_apply_and_restart_current_source(tmp_path: Path) -> None:
    key, bootstrap, _, policy = _setup(tmp_path)
    authority = GuardianMembershipAuthority(policy)
    with authority.current_source(
        expected_network_id=_NETWORK, expected_epoch=0
    ) as src:
        assert src.canonical_bytes == bootstrap.read_bytes()

    next_source = _next_source(tmp_path, 3)
    receipt, _ = _apply(authority, key, bootstrap, next_source, 0, 3)
    assert receipt.next_epoch == 3
    assert (
        receipt.next_membership_source_sha256
        == hashlib.sha256(next_source.read_bytes()).digest()
    )
    with GuardianMembershipAuthority(policy).current_source(
        expected_network_id=_NETWORK, expected_epoch=3
    ) as src:
        assert src.canonical_bytes == next_source.read_bytes()


def test_wrong_signature_network_previous_and_source_bindings_rejected(
    tmp_path: Path,
) -> None:
    key, bootstrap, _, policy = _setup(tmp_path)
    authority = GuardianMembershipAuthority(policy)
    next_source = _next_source(tmp_path, 1)
    previous_digest = hashlib.sha256(bootstrap.read_bytes()).hexdigest()
    next_digest = hashlib.sha256(next_source.read_bytes()).hexdigest()
    wrong_key = PrivateKey((902).to_bytes(32, "big"))
    cases = (
        _wire(key, 0, previous_digest, 1, next_digest, sign_with=wrong_key),
        _wire(key, 0, previous_digest, 1, next_digest, network="mainnet"),
        _wire(key, 0, "f" * 64, 1, next_digest),
        _wire(key, 0, previous_digest, 1, "e" * 64),
    )
    for wire in cases:
        with pytest.raises(GuardianMembershipTransitionError):
            authority.apply_transition(wire, next_source, _NOW)
    with authority.current_source(expected_network_id=_NETWORK, expected_epoch=0):
        pass


def test_next_source_epoch_network_and_permissions_rejected(tmp_path: Path) -> None:
    key, bootstrap, _, policy = _setup(tmp_path)
    authority = GuardianMembershipAuthority(policy)
    source = _next_source(tmp_path, 2)
    wire = _wire(
        key,
        0,
        hashlib.sha256(bootstrap.read_bytes()).hexdigest(),
        1,
        hashlib.sha256(source.read_bytes()).hexdigest(),
    )
    with pytest.raises(GuardianMembershipTransitionError):
        authority.apply_transition(wire, source, _NOW)
    source.chmod(0o644)
    with pytest.raises(GuardianMembershipTransitionError):
        authority.apply_transition(wire, source, _NOW)


@pytest.mark.parametrize(
    "mutation",
    ("whitespace", "reorder", "duplicate", "extra", "missing", "trailing"),
)
def test_noncanonical_transition_wire_rejected(tmp_path: Path, mutation: str) -> None:
    key, bootstrap, _, policy = _setup(tmp_path)
    authority = GuardianMembershipAuthority(policy)
    source = _next_source(tmp_path, 1)
    valid = _wire(
        key,
        0,
        hashlib.sha256(bootstrap.read_bytes()).hexdigest(),
        1,
        hashlib.sha256(source.read_bytes()).hexdigest(),
    )
    document = json.loads(valid)
    if mutation == "whitespace":
        candidate = json.dumps(document).encode("ascii")
    elif mutation == "reorder":
        candidate = json.dumps(
            dict(reversed(list(document.items()))), separators=(",", ":")
        ).encode("ascii")
    elif mutation == "duplicate":
        candidate = valid.replace(
            b'{"schema_version":1,',
            b'{"schema_version":1,"schema_version":1,',
            1,
        )
    elif mutation == "extra":
        candidate = valid.replace(
            b'{"schema_version":1,', b'{"extra":1,"schema_version":1,', 1
        )
    elif mutation == "missing":
        document.pop("network_id")
        candidate = json.dumps(document, separators=(",", ":")).encode("ascii")
    else:
        candidate = valid + b"\n"
    with pytest.raises(GuardianMembershipTransitionError):
        authority.apply_transition(candidate, source, _NOW)


@pytest.mark.parametrize(
    "previous_epoch,next_epoch,not_before,not_after,now",
    (
        (0, 0, _NOW - 1, _NOW + 1, _NOW),
        (1, 0, _NOW - 1, _NOW + 1, _NOW),
        (0, 1, _NOW + 1, _NOW + 2, _NOW),
        (0, 1, _NOW - 2, _NOW, _NOW),
        (0, 1, _NOW, _NOW + 86_400_001, _NOW),
    ),
)
def test_epoch_and_window_fail_closed(
    tmp_path: Path,
    previous_epoch: int,
    next_epoch: int,
    not_before: int,
    not_after: int,
    now: int,
) -> None:
    key, bootstrap, _, policy = _setup(tmp_path)
    authority = GuardianMembershipAuthority(policy)
    source = _next_source(tmp_path, max(next_epoch, 1))
    wire = _wire(
        key,
        previous_epoch,
        hashlib.sha256(bootstrap.read_bytes()).hexdigest(),
        next_epoch,
        hashlib.sha256(source.read_bytes()).hexdigest(),
        not_before_ms=not_before,
        not_after_ms=not_after,
    )
    with pytest.raises(GuardianMembershipTransitionError):
        authority.apply_transition(wire, source, now)


def test_exact_replay_nonce_reuse_and_epoch_equivocation_rejected(
    tmp_path: Path,
) -> None:
    key, bootstrap, _, policy = _setup(tmp_path)
    authority = GuardianMembershipAuthority(policy)
    source1 = _next_source(tmp_path, 1)
    _, wire1 = _apply(authority, key, bootstrap, source1, 0, 1)
    with pytest.raises(GuardianMembershipTransitionReplayError):
        authority.apply_transition(wire1, source1, _NOW)

    source2 = _next_source(tmp_path, 2)
    reused_nonce = hashlib.sha256(b"nonce-1").hexdigest()
    wire2 = _wire(
        key,
        1,
        hashlib.sha256(source1.read_bytes()).hexdigest(),
        2,
        hashlib.sha256(source2.read_bytes()).hexdigest(),
        nonce=reused_nonce,
    )
    with pytest.raises(GuardianMembershipTransitionReplayError):
        authority.apply_transition(wire2, source2, _NOW)


def test_clock_rollback_and_failed_transition_leave_current_state(
    tmp_path: Path,
) -> None:
    key, bootstrap, _, policy = _setup(tmp_path)
    authority = GuardianMembershipAuthority(policy)
    source1 = _next_source(tmp_path, 1)
    _apply(authority, key, bootstrap, source1, 0, 1)
    source2 = _next_source(tmp_path, 2)
    wire2 = _wire(
        key,
        1,
        hashlib.sha256(source1.read_bytes()).hexdigest(),
        2,
        hashlib.sha256(source2.read_bytes()).hexdigest(),
        not_before_ms=_NOW - 2_000,
        not_after_ms=_NOW + 1_000,
    )
    with pytest.raises(GuardianMembershipTransitionError):
        authority.apply_transition(wire2, source2, _NOW - 1)
    with authority.current_source(expected_network_id=_NETWORK, expected_epoch=1):
        pass


def test_current_source_restrictions_and_lock_are_enforced(tmp_path: Path) -> None:
    key, bootstrap, _, policy = _setup(tmp_path)
    first = GuardianMembershipAuthority(policy)
    second = GuardianMembershipAuthority(policy)
    source = _next_source(tmp_path, 1)
    wire = _wire(
        key,
        0,
        hashlib.sha256(bootstrap.read_bytes()).hexdigest(),
        1,
        hashlib.sha256(source.read_bytes()).hexdigest(),
    )
    with pytest.raises(GuardianMembershipTransitionError):
        with first.current_source(expected_network_id="mainnet", expected_epoch=0):
            pass
    with pytest.raises(GuardianMembershipTransitionError):
        with first.current_source(expected_network_id=_NETWORK, expected_epoch=1):
            pass
    with first.current_source(expected_network_id=_NETWORK, expected_epoch=0):
        with pytest.raises(GuardianMembershipTransitionBusyError):
            second.apply_transition(wire, source, _NOW)
    second.apply_transition(wire, source, _NOW)


def test_concurrent_duplicate_has_one_winner(tmp_path: Path) -> None:
    key, bootstrap, _, policy = _setup(tmp_path)
    authorities = [GuardianMembershipAuthority(policy) for _ in range(2)]
    source = _next_source(tmp_path, 1)
    wire = _wire(
        key,
        0,
        hashlib.sha256(bootstrap.read_bytes()).hexdigest(),
        1,
        hashlib.sha256(source.read_bytes()).hexdigest(),
    )
    outcomes: list[str] = []
    barrier = threading.Barrier(2)

    def run(authority: GuardianMembershipAuthority) -> None:
        barrier.wait()
        try:
            authority.apply_transition(wire, source, _NOW)
            outcomes.append("accepted")
        except GuardianMembershipTransitionError as error:
            outcomes.append(type(error).__name__)

    threads = [threading.Thread(target=run, args=(item,)) for item in authorities]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    assert outcomes.count("accepted") == 1
    assert len(outcomes) == 2


def test_policy_authority_and_schema_tampering_rejected(tmp_path: Path) -> None:
    _, bootstrap, ledger, policy = _setup(tmp_path)
    GuardianMembershipAuthority(policy)
    other = PrivateKey((903).to_bytes(32, "big"))
    replacement = _write_policy(
        tmp_path,
        other,
        bootstrap,
        ledger,
        suffix="-replacement",
    )
    with pytest.raises(GuardianMembershipTransitionError):
        GuardianMembershipAuthority(replacement)
    with sqlite3.connect(ledger) as connection:
        connection.execute("PRAGMA user_version = 99")
    with pytest.raises(GuardianMembershipTransitionError):
        GuardianMembershipAuthority(policy)


def test_unsafe_policy_and_ledger_paths_rejected(tmp_path: Path) -> None:
    _, _, ledger, policy = _setup(tmp_path)
    policy.chmod(0o644)
    with pytest.raises(GuardianMembershipTransitionError):
        GuardianMembershipAuthority(policy)
    policy.chmod(0o600)
    link = tmp_path / "policy-link.toml"
    link.symlink_to(policy)
    with pytest.raises(GuardianMembershipTransitionError):
        GuardianMembershipAuthority(link)
    ledger.write_bytes(b"")
    ledger.chmod(0o644)
    with pytest.raises(GuardianMembershipTransitionError):
        GuardianMembershipAuthority(policy)


def test_errors_are_redacted_and_no_signing_api_is_exposed(tmp_path: Path) -> None:
    _, _, _, policy = _setup(tmp_path)
    policy.chmod(0o644)
    with pytest.raises(GuardianMembershipTransitionError) as caught:
        GuardianMembershipAuthority(policy)
    assert str(caught.value) == "guardian membership transition rejected"
    assert str(policy) not in str(caught.value)
    source = Path(transition_module.__file__).read_text(encoding="utf-8")
    assert "PrivateKey" not in source
    assert "sign_schnorr" not in source
    assert not any(name.startswith("sign") for name in dir(transition_module))


def test_authority_rotation_survives_restart_and_controls_later_transition(
    tmp_path: Path,
) -> None:
    old_key, bootstrap, ledger, policy = _setup(tmp_path)
    new_key = PrivateKey((904).to_bytes(32, "big"))
    authority = GuardianMembershipAuthority(policy)
    wire = _rotation_wire(old_key, new_key, bootstrap)

    receipt = authority.rotate_authority(wire, _NOW)
    assert receipt.next_authority_epoch == 1
    assert receipt.next_authority_xonly_public_key == new_key.public_key_xonly.format()
    assert len(receipt.rotation_id) == 32

    next_source = _next_source(tmp_path, 1)
    old_wire = _wire(
        old_key,
        0,
        hashlib.sha256(bootstrap.read_bytes()).hexdigest(),
        1,
        hashlib.sha256(next_source.read_bytes()).hexdigest(),
    )
    restarted = GuardianMembershipAuthority(policy)
    with pytest.raises(GuardianMembershipTransitionError):
        restarted.apply_transition(old_wire, next_source, _NOW + 1)
    new_wire = _wire(
        new_key,
        0,
        hashlib.sha256(bootstrap.read_bytes()).hexdigest(),
        1,
        hashlib.sha256(next_source.read_bytes()).hexdigest(),
    )
    restarted.apply_transition(new_wire, next_source, _NOW + 1)

    with sqlite3.connect(ledger) as connection:
        assert connection.execute(
            "SELECT authority_epoch FROM current_authority"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT authority_epoch FROM membership_transitions"
        ).fetchone() == (1,)


def test_authority_rotates_at_advanced_membership_state(tmp_path: Path) -> None:
    old_key, bootstrap, ledger, policy = _setup(tmp_path)
    new_key = PrivateKey((915).to_bytes(32, "big"))
    authority = GuardianMembershipAuthority(policy)
    source = _next_source(tmp_path, 1)
    _apply(authority, old_key, bootstrap, source, 0, 1)

    stale = _rotation_wire(old_key, new_key, bootstrap)
    with pytest.raises(GuardianAuthorityRotationError):
        authority.rotate_authority(stale, _NOW + 1)
    current = _rotation_wire(
        old_key,
        new_key,
        source,
        membership_epoch=1,
        not_after_ms=_NOW + 20_000,
    )
    authority.rotate_authority(current, _NOW + 1)
    with sqlite3.connect(ledger) as connection:
        assert connection.execute(
            "SELECT authority_epoch FROM current_authority"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT membership_epoch FROM authority_rotations"
        ).fetchone() == (1,)


@pytest.mark.parametrize(
    "case",
    ("authorization", "possession", "domain-confusion", "same-key"),
)
def test_rotation_requires_both_independent_signatures(
    tmp_path: Path, case: str
) -> None:
    old_key, bootstrap, ledger, policy = _setup(tmp_path)
    new_key = PrivateKey((905).to_bytes(32, "big"))
    wrong_key = PrivateKey((906).to_bytes(32, "big"))
    if case == "authorization":
        wire = _rotation_wire(old_key, new_key, bootstrap, authorize_with=wrong_key)
    elif case == "possession":
        wire = _rotation_wire(old_key, new_key, bootstrap, prove_with=wrong_key)
    elif case == "domain-confusion":
        wire = _rotation_wire(
            old_key,
            new_key,
            bootstrap,
            possession_signs_authorization=True,
        )
    else:
        wire = _rotation_wire(old_key, old_key, bootstrap)

    authority = GuardianMembershipAuthority(policy)
    with pytest.raises(GuardianAuthorityRotationError):
        authority.rotate_authority(wire, _NOW)
    with sqlite3.connect(ledger) as connection:
        assert connection.execute(
            "SELECT authority_epoch FROM current_authority"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM authority_rotations"
        ).fetchone() == (0,)


def test_membership_signature_cannot_authorize_rotation(tmp_path: Path) -> None:
    old_key, bootstrap, _, policy = _setup(tmp_path)
    new_key = PrivateKey((916).to_bytes(32, "big"))
    source = _next_source(tmp_path, 1)
    membership_document = json.loads(
        _wire(
            old_key,
            0,
            hashlib.sha256(bootstrap.read_bytes()).hexdigest(),
            1,
            hashlib.sha256(source.read_bytes()).hexdigest(),
        )
    )
    rotation_document = json.loads(_rotation_wire(old_key, new_key, bootstrap))
    rotation_document["authorization_signature"] = membership_document["signature"]
    confused = json.dumps(rotation_document, separators=(",", ":")).encode("ascii")
    with pytest.raises(GuardianAuthorityRotationError):
        GuardianMembershipAuthority(policy).rotate_authority(confused, _NOW)


@pytest.mark.parametrize(
    "mutation",
    (
        "whitespace",
        "reorder",
        "duplicate",
        "extra",
        "missing",
        "trailing",
        "digest",
        "oversized",
    ),
)
def test_rotation_wire_is_strict_and_canonical(tmp_path: Path, mutation: str) -> None:
    old_key, bootstrap, _, policy = _setup(tmp_path)
    new_key = PrivateKey((907).to_bytes(32, "big"))
    valid = _rotation_wire(old_key, new_key, bootstrap)
    document = json.loads(valid)
    if mutation == "whitespace":
        candidate = json.dumps(document).encode("ascii")
    elif mutation == "reorder":
        candidate = json.dumps(
            dict(reversed(list(document.items()))), separators=(",", ":")
        ).encode("ascii")
    elif mutation == "duplicate":
        candidate = valid.replace(
            b'{"schema_version":1,',
            b'{"schema_version":1,"schema_version":1,',
            1,
        )
    elif mutation == "extra":
        candidate = valid.replace(
            b'{"schema_version":1,', b'{"extra":1,"schema_version":1,', 1
        )
    elif mutation == "missing":
        document.pop("network_id")
        candidate = json.dumps(document, separators=(",", ":")).encode("ascii")
    elif mutation == "trailing":
        candidate = valid + b"\n"
    elif mutation == "digest":
        document["authorization_payload_digest"] = "0" * 64
        candidate = json.dumps(document, separators=(",", ":")).encode("ascii")
    else:
        candidate = valid + b" " * 2_048
    with pytest.raises(GuardianAuthorityRotationError):
        GuardianMembershipAuthority(policy).rotate_authority(candidate, _NOW)


@pytest.mark.parametrize(
    "options",
    (
        {"next_authority_epoch": 0},
        {"next_authority_epoch": 2},
        {"membership_epoch": 1},
        {"network": "mainnet"},
        {"not_before_ms": _NOW + 1, "not_after_ms": _NOW + 2},
        {"not_before_ms": _NOW - 2, "not_after_ms": _NOW},
        {"not_before_ms": _NOW, "not_after_ms": _NOW + 86_400_001},
    ),
)
def test_rotation_state_and_window_bindings_fail_closed(
    tmp_path: Path, options: dict[str, object]
) -> None:
    old_key, bootstrap, _, policy = _setup(tmp_path)
    new_key = PrivateKey((908).to_bytes(32, "big"))
    wire = _rotation_wire(old_key, new_key, bootstrap, **options)
    with pytest.raises(GuardianAuthorityRotationError):
        GuardianMembershipAuthority(policy).rotate_authority(wire, _NOW)


def test_rotation_replay_nonce_reuse_old_key_and_clock_rollback_rejected(
    tmp_path: Path,
) -> None:
    key0, bootstrap, ledger, policy = _setup(tmp_path)
    key1 = PrivateKey((909).to_bytes(32, "big"))
    key2 = PrivateKey((910).to_bytes(32, "big"))
    authority = GuardianMembershipAuthority(policy)
    wire1 = _rotation_wire(key0, key1, bootstrap)
    authority.rotate_authority(wire1, _NOW)
    with pytest.raises(GuardianAuthorityRotationReplayError):
        authority.rotate_authority(wire1, _NOW)

    reused_nonce = hashlib.sha256(b"authority-rotation-1").hexdigest()
    with pytest.raises(GuardianAuthorityRotationReplayError):
        authority.rotate_authority(
            _rotation_wire(
                key1,
                key2,
                bootstrap,
                previous_authority_epoch=1,
                next_authority_epoch=2,
                nonce=reused_nonce,
            ),
            _NOW + 1,
        )
    with pytest.raises(GuardianAuthorityRotationReplayError):
        authority.rotate_authority(
            _rotation_wire(
                key1,
                key0,
                bootstrap,
                previous_authority_epoch=1,
                next_authority_epoch=2,
            ),
            _NOW + 1,
        )
    with pytest.raises(GuardianAuthorityRotationError):
        authority.rotate_authority(
            _rotation_wire(
                key1,
                key2,
                bootstrap,
                previous_authority_epoch=1,
                next_authority_epoch=2,
                not_before_ms=_NOW - 2_000,
                not_after_ms=_NOW + 2_000,
            ),
            _NOW - 1,
        )
    authority.rotate_authority(
        _rotation_wire(
            key1,
            key2,
            bootstrap,
            previous_authority_epoch=1,
            next_authority_epoch=2,
        ),
        _NOW + 1,
    )
    with sqlite3.connect(ledger) as connection:
        assert connection.execute(
            "SELECT authority_epoch FROM current_authority"
        ).fetchone() == (2,)
        assert connection.execute(
            "SELECT COUNT(*) FROM authority_rotations"
        ).fetchone() == (2,)


def test_exact_v1_ledger_migrates_transactionally_and_preserves_history(
    tmp_path: Path,
) -> None:
    key, bootstrap, ledger, policy = _setup(tmp_path)
    authority = GuardianMembershipAuthority(policy)
    next_source = _next_source(tmp_path, 1)
    _apply(authority, key, bootstrap, next_source, 0, 1)
    _downgrade_fixture_to_v1(ledger)

    restarted = GuardianMembershipAuthority(policy)
    with restarted.current_source(expected_network_id=_NETWORK, expected_epoch=1):
        pass
    with sqlite3.connect(ledger) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (2,)
        assert connection.execute(
            "SELECT authority_epoch FROM membership_transitions"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT authority_epoch FROM current_authority"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT high_water_ms FROM membership_clock"
        ).fetchone() == (_NOW,)


def test_unexpected_v1_schema_fails_before_migration(tmp_path: Path) -> None:
    _, _, ledger, policy = _setup(tmp_path)
    GuardianMembershipAuthority(policy)
    _downgrade_fixture_to_v1(ledger)
    with sqlite3.connect(ledger) as connection:
        connection.execute("CREATE TABLE unexpected(value INTEGER) STRICT")

    with pytest.raises(GuardianMembershipTransitionError):
        GuardianMembershipAuthority(policy)
    with sqlite3.connect(ledger) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (1,)
        names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert "unexpected" in names
        assert "current_authority" not in names


def test_tampered_v1_anchor_fails_before_migration(tmp_path: Path) -> None:
    _, _, ledger, policy = _setup(tmp_path)
    GuardianMembershipAuthority(policy)
    _downgrade_fixture_to_v1(ledger)
    with sqlite3.connect(ledger) as connection:
        connection.execute(
            "UPDATE membership_authority SET network_id = 'mainnet' "
            "WHERE singleton = 1"
        )

    with pytest.raises(GuardianMembershipTransitionError):
        GuardianMembershipAuthority(policy)
    with sqlite3.connect(ledger) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (1,)
        assert connection.execute(
            "SELECT network_id FROM membership_authority"
        ).fetchone() == ("mainnet",)
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name = 'current_authority'"
            ).fetchone()
            is None
        )


@pytest.mark.parametrize(
    "tamper",
    ("rotation-count", "key-count", "current-pair", "genesis", "trigger"),
)
def test_v2_authority_state_tampering_fails_closed(tmp_path: Path, tamper: str) -> None:
    old_key, bootstrap, ledger, policy = _setup(tmp_path)
    new_key = PrivateKey((917).to_bytes(32, "big"))
    GuardianMembershipAuthority(policy).rotate_authority(
        _rotation_wire(old_key, new_key, bootstrap), _NOW
    )
    with sqlite3.connect(ledger) as connection:
        if tamper == "rotation-count":
            connection.execute("DELETE FROM authority_rotations")
        elif tamper == "key-count":
            connection.execute(
                "DELETE FROM authority_key_history WHERE authority_epoch = 1"
            )
        elif tamper == "current-pair":
            replacement = PrivateKey((918).to_bytes(32, "big"))
            connection.execute(
                "UPDATE current_authority SET authority_xonly_public_key = ?",
                (replacement.public_key_xonly.format(),),
            )
        elif tamper == "genesis":
            replacement = PrivateKey((919).to_bytes(32, "big"))
            connection.execute(
                "UPDATE authority_key_history "
                "SET authority_xonly_public_key = ? WHERE authority_epoch = 0",
                (replacement.public_key_xonly.format(),),
            )
        else:
            connection.execute(
                "CREATE TRIGGER unexpected_rotation_trigger "
                "AFTER INSERT ON authority_rotations BEGIN SELECT 1; END"
            )

    with pytest.raises(GuardianMembershipTransitionError):
        GuardianMembershipAuthority(policy)


def test_concurrent_duplicate_rotation_has_one_winner(tmp_path: Path) -> None:
    old_key, bootstrap, ledger, policy = _setup(tmp_path)
    new_key = PrivateKey((911).to_bytes(32, "big"))
    authorities = [GuardianMembershipAuthority(policy) for _ in range(2)]
    wire = _rotation_wire(old_key, new_key, bootstrap)
    outcomes: list[str] = []
    barrier = threading.Barrier(2)

    def run(authority: GuardianMembershipAuthority) -> None:
        barrier.wait()
        try:
            authority.rotate_authority(wire, _NOW)
            outcomes.append("accepted")
        except GuardianAuthorityRotationError as error:
            outcomes.append(type(error).__name__)

    threads = [threading.Thread(target=run, args=(item,)) for item in authorities]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    assert outcomes.count("accepted") == 1
    assert len(outcomes) == 2
    with sqlite3.connect(ledger) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM authority_rotations"
        ).fetchone() == (1,)


def test_rotation_and_membership_transition_serialize(tmp_path: Path) -> None:
    old_key, bootstrap, ledger, policy = _setup(tmp_path)
    new_key = PrivateKey((912).to_bytes(32, "big"))
    source = _next_source(tmp_path, 1)
    rotation = _rotation_wire(old_key, new_key, bootstrap)
    transition = _wire(
        old_key,
        0,
        hashlib.sha256(bootstrap.read_bytes()).hexdigest(),
        1,
        hashlib.sha256(source.read_bytes()).hexdigest(),
    )
    authorities = [GuardianMembershipAuthority(policy) for _ in range(2)]
    outcomes: list[str] = []
    barrier = threading.Barrier(2)

    def rotate() -> None:
        barrier.wait()
        try:
            authorities[0].rotate_authority(rotation, _NOW)
            outcomes.append("rotation")
        except GuardianAuthorityRotationError:
            outcomes.append("rotation-rejected")

    def transition_membership() -> None:
        barrier.wait()
        try:
            authorities[1].apply_transition(transition, source, _NOW)
            outcomes.append("transition")
        except GuardianMembershipTransitionError:
            outcomes.append("transition-rejected")

    threads = [
        threading.Thread(target=rotate),
        threading.Thread(target=transition_membership),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    assert len(outcomes) == 2
    assert sum(item in {"rotation", "transition"} for item in outcomes) == 1
    with sqlite3.connect(ledger) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM authority_rotations").fetchone()[0]
            + connection.execute(
                "SELECT COUNT(*) FROM membership_transitions"
            ).fetchone()[0]
            == 1
        )


def test_rotation_receipt_is_nonconstructible_nonserializable_and_redacted(
    tmp_path: Path,
) -> None:
    old_key, bootstrap, _, policy = _setup(tmp_path)
    new_key = PrivateKey((913).to_bytes(32, "big"))
    authority = GuardianMembershipAuthority(policy)
    receipt = authority.rotate_authority(
        _rotation_wire(old_key, new_key, bootstrap), _NOW
    )
    with pytest.raises(TypeError):
        GuardianAuthorityRotationReceipt()
    with pytest.raises(TypeError):
        pickle.dumps(receipt)
    with pytest.raises(GuardianAuthorityRotationError) as caught:
        authority.rotate_authority(b"not-json", _NOW)
    assert str(caught.value) == "guardian authority rotation rejected"
    assert str(policy) not in str(caught.value)
    assert "PrivateKey" not in Path(transition_module.__file__).read_text(
        encoding="utf-8"
    )


def test_rotation_busy_error_is_distinct(tmp_path: Path) -> None:
    old_key, bootstrap, _, policy = _setup(tmp_path)
    new_key = PrivateKey((914).to_bytes(32, "big"))
    first = GuardianMembershipAuthority(policy)
    second = GuardianMembershipAuthority(policy)
    wire = _rotation_wire(old_key, new_key, bootstrap)
    with first.current_source(expected_network_id=_NETWORK, expected_epoch=0):
        with pytest.raises(GuardianAuthorityRotationBusyError):
            second.rotate_authority(wire, _NOW)
