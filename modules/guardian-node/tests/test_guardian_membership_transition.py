"""Tests for owner-local signed Guardian membership transitions."""

# Test helpers intentionally inspect durable state and use test-only keys.
# pylint: disable=missing-function-docstring,protected-access,too-many-arguments
# pylint: disable=too-many-positional-arguments

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from pathlib import Path

import pytest
from coincurve import PrivateKey

import jaeger.guardian_membership_transition as transition_module
from jaeger.guardian_membership_source import MEMBERSHIP_SOURCE_PROTOCOL_ID
from jaeger.guardian_membership_transition import (
    MEMBERSHIP_TRANSITION_DIGEST_DOMAIN,
    MEMBERSHIP_TRANSITION_PROTOCOL_ID,
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
