"""Tests for the owner-only local Guardian ballot ingress."""

# Pytest test names provide the scenario descriptions; establishment tests
# intentionally exercise module internals for registration-conflict coverage.
# pylint: disable=missing-function-docstring,protected-access,duplicate-code
# pylint: disable=too-many-arguments,too-few-public-methods
# pylint: disable=too-many-function-args,unidiomatic-typecheck
# pylint: disable=use-implicit-booleaness-not-comparison

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import os
import pickle
import shutil
import tempfile
import threading
from dataclasses import replace
from pathlib import Path

import pytest
from coincurve import PrivateKey

import jaeger.ballot_ingress as ingress_module
import jaeger.guardian_membership_source as source_module
from jaeger.ballot_ingress import (
    BallotContext,
    BallotIngress,
    BallotIngressError,
    BallotIngressServer,
    IngressAck,
    submit_to_ingress,
)
from jaeger.ensemble import EnsembleCandidate
from jaeger.guardian_membership_source import (
    MAX_MEMBERSHIP_EPOCH,
    MEMBERSHIP_SOURCE_PROTOCOL_ID,
    load_guardian_membership_source,
)
from jaeger.signed_ballots import MAX_BALLOT_WIRE_BYTES, BallotSession, ReplayLedger
from tests.test_signed_ballots import (
    MODEL_HASH,
    NOW_MS,
    POLICY_HASH,
    make_collector,
    make_rule,
    sign_vote,
)
from tests.test_signed_ballots import BallotContext as SigningContext

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="membership source loader requires POSIX file controls"
)

_NETWORK = "mainnet"
_SESSION_NONCE = "4" * 64
_VALID_FROM_MS = NOW_MS - 1_000
_VALID_UNTIL_MS = NOW_MS + 600_000
_STABLE_ERROR = "invalid ballot session establishment"


def _make_members(
    count: int = 5, *, key_offset: int = 0
) -> list[tuple[PrivateKey, dict]]:
    members = []
    for index in range(count):
        private = PrivateKey((key_offset + index + 1).to_bytes(32, "big"))
        members.append(
            (
                private,
                {
                    "guardian_id": hashlib.sha256(
                        b"ingress-guardian-%d" % (key_offset + index)
                    ).hexdigest(),
                    "xonly_public_key": private.public_key_xonly.format().hex(),
                    "model_tier": "8b",
                    "model_artifact_sha256": MODEL_HASH,
                },
            )
        )
    members.sort(key=lambda pair: pair[1]["guardian_id"])
    return members


def _canonical_source_bytes(
    members: list[tuple[PrivateKey, dict]],
    *,
    epoch: int = 0,
    network: str = _NETWORK,
) -> bytes:
    document = {
        "schema_version": 1,
        "protocol_id": MEMBERSHIP_SOURCE_PROTOCOL_ID,
        "network_id": network,
        "epoch": epoch,
        "members": [member for _, member in members],
    }
    return json.dumps(document, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def _write_source(directory: Path, raw: bytes, mode: int = 0o600) -> Path:
    directory.chmod(0o700)
    path = directory / "guardian-membership-source.json"
    path.write_bytes(raw)
    path.chmod(mode)
    return path


def _make_candidate() -> EnsembleCandidate:
    return EnsembleCandidate.create(make_rule(), POLICY_HASH, MODEL_HASH)


def _establish(
    ingress: BallotIngress,
    path: Path,
    candidate: EnsembleCandidate,
    *,
    epoch: object = 0,
    network: object = _NETWORK,
    session_nonce: str = _SESSION_NONCE,
) -> BallotContext:
    return ingress.establish_session(
        path,
        expected_network_id=network,  # type: ignore[arg-type]
        expected_epoch=epoch,  # type: ignore[arg-type]
        candidate=candidate,
        session_nonce=session_nonce,
        valid_from_ms=_VALID_FROM_MS,
        valid_until_ms=_VALID_UNTIL_MS,
    )


def _expected_views(path: Path, candidate: EnsembleCandidate):
    """Independently derive the snapshot and session the source must bind."""
    source = load_guardian_membership_source(path, expected_network_id=_NETWORK)
    snapshot = source.to_membership_snapshot()
    session = BallotSession.create(
        candidate,
        snapshot,
        source.to_ballot_signers(),
        network_id=source.network_id,
        session_nonce=_SESSION_NONCE,
        valid_from_ms=_VALID_FROM_MS,
        valid_until_ms=_VALID_UNTIL_MS,
    )
    return snapshot, session


def make_ingress(tmp_path):
    members = _make_members()
    path = _write_source(tmp_path, _canonical_source_bytes(members))
    candidate = _make_candidate()
    collector, ledger_path = make_collector(tmp_path)
    ingress = BallotIngress(collector)
    _establish(ingress, path, candidate)
    snapshot, session = _expected_views(path, candidate)
    context = SigningContext(
        candidate, snapshot, session, tuple(private for private, _ in members)
    )
    return context, ingress, ledger_path


def test_establish_session_derives_source_bound_context(tmp_path) -> None:
    members = _make_members()
    raw = _canonical_source_bytes(members)
    path = _write_source(tmp_path, raw)
    candidate = _make_candidate()
    collector, _ = make_collector(tmp_path)
    ingress = BallotIngress(collector)

    established = _establish(ingress, path, candidate)

    snapshot, session = _expected_views(path, candidate)
    assert set(ingress._contexts) == {session.session_id}
    registered = ingress._contexts[session.session_id]
    assert established == registered
    assert type(registered) is BallotContext
    assert registered.candidate == candidate
    assert registered.snapshot == snapshot
    assert registered.session == session
    assert (
        registered.snapshot.membership_source_sha256 == hashlib.sha256(raw).hexdigest()
    )
    assert [signer.guardian_id for signer in registered.session.signers] == [
        member["guardian_id"] for _, member in members
    ]

    context = SigningContext(
        candidate, snapshot, session, tuple(private for private, _ in members)
    )
    wire = sign_vote(context, 0).to_wire()
    assert ingress.process(wire, NOW_MS).status == "accepted"


def test_establish_session_loads_source_once_on_success(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_source(tmp_path, _canonical_source_bytes(_make_members()))
    candidate = _make_candidate()
    collector, _ = make_collector(tmp_path)
    ingress = BallotIngress(collector)
    calls: list[tuple[Path, str]] = []
    real_loader = ingress_module.load_guardian_membership_source

    def spy_loader(
        load_path: Path, *, expected_network_id: str
    ) -> source_module.GuardianMembershipSource:
        calls.append((load_path, expected_network_id))
        return real_loader(load_path, expected_network_id=expected_network_id)

    monkeypatch.setattr(ingress_module, "load_guardian_membership_source", spy_loader)

    established = _establish(ingress, path, candidate)

    assert calls == [(path, _NETWORK)]
    assert ingress._contexts == {established.session.session_id: established}


def test_establish_session_is_idempotent_for_exact_same_derivation(tmp_path) -> None:
    context, ingress, ledger_path = make_ingress(tmp_path)
    path = tmp_path / "guardian-membership-source.json"

    established = _establish(ingress, path, context.candidate)

    assert set(ingress._contexts) == {context.session.session_id}
    assert established == ingress._contexts[context.session.session_id]
    wire = sign_vote(context, 0).to_wire()
    assert ingress.process(wire, NOW_MS).status == "accepted"
    assert ReplayLedger(ledger_path).session_wires(context.session.session_id) == (
        wire,
    )


def test_conflicting_same_session_context_rejected(tmp_path) -> None:
    context, ingress, _ = make_ingress(tmp_path)
    conflicting_session = replace(context.session, valid_from_ms=_VALID_FROM_MS + 1)
    conflicting = ingress_module._derive_context(
        context.candidate, context.snapshot, conflicting_session
    )

    with pytest.raises(BallotIngressError) as caught:
        ingress._register_context(conflicting)
    assert str(caught.value) == _STABLE_ERROR
    assert ingress._contexts[context.session.session_id].session == context.session


def test_expected_epoch_bounds_accepted(tmp_path) -> None:
    for epoch in (0, MAX_MEMBERSHIP_EPOCH):
        case_dir = tmp_path / f"case-{epoch}"
        case_dir.mkdir()
        members = _make_members()
        path = _write_source(case_dir, _canonical_source_bytes(members, epoch=epoch))
        candidate = _make_candidate()
        collector, _ = make_collector(case_dir)
        ingress = BallotIngress(collector)
        _establish(ingress, path, candidate, epoch=epoch)
        assert len(ingress._contexts) == 1


@pytest.mark.parametrize(
    "bad_epoch",
    (True, False, "0", 1.5, 1.0, -1, MAX_MEMBERSHIP_EPOCH + 1),
)
def test_expected_epoch_type_and_range_fail_before_file_access(
    tmp_path, monkeypatch: pytest.MonkeyPatch, bad_epoch
) -> None:
    path = _write_source(tmp_path, _canonical_source_bytes(_make_members()))
    loads: list[tuple[Path, str]] = []

    def fail_if_called(
        load_path: Path, *, expected_network_id: str
    ) -> source_module.GuardianMembershipSource:
        loads.append((load_path, expected_network_id))
        raise AssertionError("source reader must not run")

    monkeypatch.setattr(
        ingress_module, "load_guardian_membership_source", fail_if_called
    )
    collector, _ = make_collector(tmp_path)
    ingress = BallotIngress(collector)
    with pytest.raises(BallotIngressError) as caught:
        _establish(ingress, path, _make_candidate(), epoch=bad_epoch)
    assert str(caught.value) == _STABLE_ERROR
    assert str(bad_epoch) not in str(caught.value)
    assert loads == []
    assert ingress._contexts == {}


def test_expected_epoch_mismatch_rejected_after_read(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_source(tmp_path, _canonical_source_bytes(_make_members()))
    reads: list[Path] = []
    real_reader = source_module._read_owner_source_file

    def spy_reader(read_path: Path) -> bytes:
        reads.append(read_path)
        return real_reader(read_path)

    monkeypatch.setattr(source_module, "_read_owner_source_file", spy_reader)
    collector, _ = make_collector(tmp_path)
    ingress = BallotIngress(collector)
    with pytest.raises(BallotIngressError) as caught:
        _establish(ingress, path, _make_candidate(), epoch=1)
    assert str(caught.value) == _STABLE_ERROR
    assert reads == [path]
    assert ingress._contexts == {}


def test_expected_network_mismatch_rejected_redacted(tmp_path) -> None:
    path = _write_source(tmp_path, _canonical_source_bytes(_make_members()))
    collector, _ = make_collector(tmp_path)
    ingress = BallotIngress(collector)
    with pytest.raises(BallotIngressError) as caught:
        _establish(ingress, path, _make_candidate(), network="testnet-1")
    assert str(caught.value) == _STABLE_ERROR
    assert "testnet-1" not in str(caught.value)
    assert _NETWORK not in str(caught.value)
    assert str(path) not in str(caught.value)
    assert ingress._contexts == {}


def test_source_change_binds_different_snapshot_and_session(tmp_path) -> None:
    members_a = _make_members()
    path = _write_source(tmp_path, _canonical_source_bytes(members_a))
    candidate = _make_candidate()
    collector, _ = make_collector(tmp_path)
    ingress = BallotIngress(collector)
    _establish(ingress, path, candidate)
    snapshot_a, session_a = _expected_views(path, candidate)

    members_b = _make_members(key_offset=100)
    raw_b = _canonical_source_bytes(members_b)
    path.write_bytes(raw_b)
    path.chmod(0o600)
    _establish(ingress, path, candidate)
    snapshot_b, session_b = _expected_views(path, candidate)

    assert snapshot_a.snapshot_id != snapshot_b.snapshot_id
    assert snapshot_a.membership_source_sha256 != snapshot_b.membership_source_sha256
    assert session_a.session_id != session_b.session_id
    assert set(ingress._contexts) == {session_a.session_id, session_b.session_id}
    assert ingress._contexts[session_b.session_id].snapshot == snapshot_b


def test_distinct_sources_remain_session_and_signer_isolated(tmp_path) -> None:
    source_a_dir = tmp_path / "source-a"
    source_b_dir = tmp_path / "source-b"
    source_a_dir.mkdir()
    source_b_dir.mkdir()
    members_a = _make_members()
    members_b = _make_members(key_offset=100)
    path_a = _write_source(source_a_dir, _canonical_source_bytes(members_a))
    path_b = _write_source(source_b_dir, _canonical_source_bytes(members_b))
    candidate = _make_candidate()
    collector, _ = make_collector(tmp_path)
    ingress = BallotIngress(collector)

    established_a = _establish(ingress, path_a, candidate)
    established_b = _establish(ingress, path_b, candidate)
    context_a = SigningContext(
        candidate,
        established_a.snapshot,
        established_a.session,
        tuple(private for private, _ in members_a),
    )
    context_b = SigningContext(
        candidate,
        established_b.snapshot,
        established_b.session,
        tuple(private for private, _ in members_b),
    )

    forged_a = sign_vote(context_a, 1, signing_key=members_b[1][0]).to_wire()
    assert ingress.process(forged_a, NOW_MS).status == "rejected"
    assert (
        ingress.process(sign_vote(context_a, 0).to_wire(), NOW_MS).status == "accepted"
    )
    assert (
        ingress.process(sign_vote(context_b, 0).to_wire(), NOW_MS).status == "accepted"
    )
    assert established_a.snapshot != established_b.snapshot
    assert established_a.session.session_id != established_b.session.session_id
    assert set(ingress._contexts) == {
        established_a.session.session_id,
        established_b.session.session_id,
    }


def test_direct_context_construction_and_public_register_disabled(tmp_path) -> None:
    context, ingress, _ = make_ingress(tmp_path)
    registered = ingress._contexts[context.session.session_id]
    with pytest.raises(TypeError):
        BallotContext()
    with pytest.raises(TypeError):
        BallotContext(context.candidate, context.snapshot, context.session)
    with pytest.raises(TypeError):
        dataclasses.replace(registered)
    with pytest.raises(TypeError):
        pickle.dumps(registered)
    assert not hasattr(ingress, "register")


@pytest.mark.parametrize("mode", (0o644, 0o640, 0o777, 0o4000 | 0o600))
def test_unsafe_source_file_rejected_with_redacted_error(tmp_path, mode) -> None:
    path = _write_source(tmp_path, _canonical_source_bytes(_make_members()), mode=mode)
    collector, _ = make_collector(tmp_path)
    ingress = BallotIngress(collector)
    with pytest.raises(BallotIngressError) as caught:
        _establish(ingress, path, _make_candidate())
    assert str(caught.value) == _STABLE_ERROR
    assert str(path) not in str(caught.value)
    assert _NETWORK not in str(caught.value)
    assert ingress._contexts == {}


def test_missing_source_file_rejected_redacted(tmp_path) -> None:
    tmp_path.chmod(0o700)
    missing = tmp_path / "absent.json"
    collector, _ = make_collector(tmp_path)
    ingress = BallotIngress(collector)
    with pytest.raises(BallotIngressError) as caught:
        _establish(ingress, missing, _make_candidate())
    assert str(caught.value) == _STABLE_ERROR
    assert str(missing) not in str(caught.value)
    assert ingress._contexts == {}


def test_invalid_session_inputs_rejected_redacted(tmp_path) -> None:
    members = _make_members()
    path = _write_source(tmp_path, _canonical_source_bytes(members))
    collector, _ = make_collector(tmp_path)
    ingress = BallotIngress(collector)
    with pytest.raises(BallotIngressError) as caught:
        _establish(ingress, path, _make_candidate(), session_nonce="not-hex")
    assert str(caught.value) == _STABLE_ERROR
    assert "not-hex" not in str(caught.value)
    assert ingress._contexts == {}


def test_process_accepts_exact_bytes_and_makes_retry_idempotent(tmp_path) -> None:
    context, ingress, ledger_path = make_ingress(tmp_path)
    wire = sign_vote(context, 0).to_wire()

    accepted = ingress.process(wire, NOW_MS)
    duplicate = ingress.process(wire, NOW_MS)

    assert accepted.status == "accepted"
    assert duplicate.status == "duplicate"
    assert accepted.payload_digest == duplicate.payload_digest
    assert ReplayLedger(ledger_path).session_wires(context.session.session_id) == (
        wire,
    )


def test_process_rejects_unknown_tampered_and_oversized_input(tmp_path) -> None:
    context, ingress, ledger_path = make_ingress(tmp_path)
    unknown = replace(sign_vote(context, 0), session_id="f" * 64).to_wire()
    tampered = bytearray(sign_vote(context, 1).to_wire())
    tampered[-2] ^= 1

    assert ingress.process(unknown, NOW_MS).status == "rejected"
    assert ingress.process(bytes(tampered), NOW_MS).status == "rejected"
    assert (
        ingress.process(b"x" * (MAX_BALLOT_WIRE_BYTES + 1), NOW_MS).status == "rejected"
    )
    assert ReplayLedger(ledger_path).session_wires(context.session.session_id) == ()


def test_conflicting_second_ballot_is_not_reported_as_duplicate(tmp_path) -> None:
    context, ingress, _ = make_ingress(tmp_path)
    first = sign_vote(context, 0).to_wire()
    conflicting = sign_vote(context, 0, decision="reject", nonce="e" * 64).to_wire()

    assert ingress.process(first, NOW_MS).status == "accepted"
    assert ingress.process(conflicting, NOW_MS).status == "rejected"


def test_ack_requires_canonical_exact_schema() -> None:
    ack = IngressAck("accepted", "a" * 64, "b" * 64)
    assert IngressAck.from_wire(ack.to_wire()) == ack
    with pytest.raises(BallotIngressError):
        IngressAck.from_wire(ack.to_wire() + b" ")
    with pytest.raises(BallotIngressError, match="identifiers"):
        IngressAck("accepted", "", "").to_wire()


@pytest.mark.asyncio
async def test_owner_only_unix_server_round_trip(tmp_path) -> None:
    context, ingress, ledger_path = make_ingress(tmp_path)
    socket_dir = Path(tempfile.mkdtemp(prefix="prom-in-"))
    os.chmod(socket_dir, 0o700)
    socket_path = socket_dir / "guardian.sock"
    server = BallotIngressServer(socket_path, ingress, now_ms=lambda: NOW_MS)
    try:
        await server.start()
        assert socket_path.stat().st_mode & 0o777 == 0o600
        wire = sign_vote(context, 0).to_wire()
        ack = await submit_to_ingress(socket_path, wire)
        assert ack.status == "accepted"
        assert ReplayLedger(ledger_path).session_wires(context.session.session_id) == (
            wire,
        )
    finally:
        await server.close()
        shutil.rmtree(socket_dir)
    assert not socket_path.exists()


@pytest.mark.asyncio
async def test_server_rejects_oversize_prefix_without_reading_body(tmp_path) -> None:
    _, ingress, _ = make_ingress(tmp_path)
    socket_dir = Path(tempfile.mkdtemp(prefix="prom-in-"))
    os.chmod(socket_dir, 0o700)
    socket_path = socket_dir / "guardian.sock"
    server = BallotIngressServer(socket_path, ingress, now_ms=lambda: NOW_MS)
    try:
        await server.start()
        reader, writer = await asyncio.open_unix_connection(socket_path)
        writer.write((MAX_BALLOT_WIRE_BYTES + 1).to_bytes(4, "big"))
        await writer.drain()
        size = int.from_bytes(await reader.readexactly(4), "big")
        ack = IngressAck.from_wire(await reader.readexactly(size))
        assert ack.status == "rejected"
        writer.close()
        await writer.wait_closed()
    finally:
        await server.close()
        shutil.rmtree(socket_dir)


@pytest.mark.asyncio
async def test_server_keeps_worker_permit_until_timed_out_processing_finishes() -> None:
    class BlockingIngress:
        def __init__(self) -> None:
            self.started = threading.Event()
            self.release = threading.Event()

        def process(self, wire: bytes, now_ms: int) -> IngressAck:
            del now_ms
            self.started.set()
            self.release.wait()
            return IngressAck("accepted", "a" * 64, hashlib.sha256(wire).hexdigest())

    socket_dir = Path(tempfile.mkdtemp(prefix="prom-in-"))
    os.chmod(socket_dir, 0o700)
    socket_path = socket_dir / "guardian.sock"
    ingress = BlockingIngress()
    server = BallotIngressServer(
        socket_path,
        ingress,
        now_ms=lambda: NOW_MS,
        max_connections=1,
        io_timeout_seconds=0.01,
    )
    wire = b"blocked ballot"
    try:
        await server.start()
        with pytest.raises(asyncio.IncompleteReadError):
            await submit_to_ingress(socket_path, wire, timeout_seconds=0.1)
        assert await asyncio.to_thread(ingress.started.wait, 0.5)

        busy = await submit_to_ingress(socket_path, wire)
        assert busy == IngressAck("busy", "", "")

        ingress.release.set()
        for _ in range(50):
            try:
                accepted = await submit_to_ingress(socket_path, wire)
            except asyncio.IncompleteReadError:
                await asyncio.sleep(0.01)
            else:
                if accepted.status == "accepted":
                    break
                assert accepted == IngressAck("busy", "", "")
                await asyncio.sleep(0.01)
        else:
            pytest.fail("worker permit was not released after processing completed")
    finally:
        ingress.release.set()
        await server.close()
        shutil.rmtree(socket_dir)


@pytest.mark.asyncio
async def test_submit_rejects_ack_for_a_different_ballot() -> None:
    class MismatchedIngress:
        def process(self, wire: bytes, now_ms: int) -> IngressAck:
            del wire, now_ms
            return IngressAck("accepted", "a" * 64, "b" * 64)

    socket_dir = Path(tempfile.mkdtemp(prefix="prom-in-"))
    os.chmod(socket_dir, 0o700)
    socket_path = socket_dir / "guardian.sock"
    server = BallotIngressServer(
        socket_path, MismatchedIngress(), now_ms=lambda: NOW_MS
    )
    try:
        await server.start()
        with pytest.raises(BallotIngressError, match="does not match ballot"):
            await submit_to_ingress(socket_path, b"exact ballot")
    finally:
        await server.close()
        shutil.rmtree(socket_dir)


def test_server_rejects_unsafe_parent_and_existing_path(tmp_path) -> None:
    context, ingress, _ = make_ingress(tmp_path)
    del context
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o755)
    with pytest.raises(BallotIngressError, match="owner-controlled"):
        BallotIngressServer(unsafe / "guardian.sock", ingress, now_ms=lambda: NOW_MS)

    safe = tmp_path / "safe"
    safe.mkdir(mode=0o700)
    existing = safe / "guardian.sock"
    existing.write_text("do not replace", encoding="ascii")
    with pytest.raises(BallotIngressError, match="already exists"):
        BallotIngressServer(existing, ingress, now_ms=lambda: NOW_MS)
