"""Tests for the owner-only local Guardian ballot ingress."""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest

from jaeger.ballot_ingress import (
    BallotContext,
    BallotIngress,
    BallotIngressError,
    BallotIngressServer,
    IngressAck,
    submit_to_ingress,
)
from jaeger.signed_ballots import MAX_BALLOT_WIRE_BYTES, ReplayLedger
from tests.test_signed_ballots import NOW_MS, make_collector, make_context, sign_vote


def make_ingress(tmp_path):
    context = make_context()
    collector, ledger_path = make_collector(tmp_path)
    ingress = BallotIngress(collector)
    ingress.register(
        BallotContext(context.candidate, context.snapshot, context.session)
    )
    return context, ingress, ledger_path


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
