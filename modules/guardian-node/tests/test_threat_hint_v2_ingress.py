"""Adversarial tests for the owner-only ThreatHint-v2 ingress boundary."""

# Pytest test names provide the scenario descriptions.
# pylint: disable=missing-function-docstring,too-few-public-methods
# Pytest fixtures intentionally shadow their factory names; exact emptiness
# assertions stay explicit for protocol clarity.
# pylint: disable=redefined-outer-name,use-implicit-booleaness-not-comparison

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import stat
import tempfile
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

import pytest

from jaeger import threat_hint_v2_ingress as ingress_module
from jaeger.threat_hint_v2_ingress import (
    MAX_TRANSPORT_PAYLOAD_BYTES,
    MAX_V2_INGRESS_ACK_BYTES,
    THREAT_HINT_V2_PROTOCOL_VERSION,
    ThreatHintV2Ingress,
    ThreatHintV2IngressAck,
    ThreatHintV2IngressError,
    ThreatHintV2IngressServer,
)
from jaeger.threat_hint_v2_promotion import (
    ThreatHintV2PromotionBusyError,
    ThreatHintV2PromotionError,
    ThreatHintV2PromotionReplayError,
    ThreatHintV2PromotionUnavailableError,
)
from jaeger.threat_hint_v2_transport import ThreatHintV2TransportPayload

VECTOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "threat-hint"
    / "tests"
    / "vectors"
    / "threat-hint-v2-transport-v1.json"
)
NOW_SECONDS = 1_800_000_000


def _reject_duplicate_keys(items: Iterable[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate vector key")
        result[key] = value
    return result


def _base_case() -> dict:
    parsed = json.loads(
        VECTOR_PATH.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
    )
    return {case["name"]: case for case in parsed["valid_cases"]}[
        "base_review_required"
    ]


def _valid_wire() -> bytes:
    return bytes.fromhex(_base_case()["wire_hex"])


def _trusted_network() -> str:
    return str(_base_case()["trusted_network_id"])


def _parsed() -> ThreatHintV2TransportPayload:
    return ThreatHintV2TransportPayload.parse_canonical(
        _valid_wire(), _trusted_network()
    )


class _StubPromotion:
    """Recording promotion stand-in with a configurable failure outcome."""

    def __init__(self, failure: Optional[Exception] = None) -> None:
        self.failure = failure
        self.calls: list[tuple[bytes, bytes, bytes, bytes, int]] = []

    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def promote(
        self,
        envelope_wire: bytes,
        bundle_wire: bytes,
        approval_wire: bytes,
        *,
        report_nonce: bytes,
        current_time: int,
    ) -> object:
        self.calls.append(
            (envelope_wire, bundle_wire, approval_wire, report_nonce, current_time)
        )
        if self.failure is not None:
            raise self.failure
        return object()


class _StubResolver:
    """Recording resolver stand-in returning one fixed trusted answer."""

    def __init__(self, answer: object) -> None:
        self.answer = answer
        self.lookups: list[bytes] = []

    def resolve(self, report_nonce: bytes) -> Optional[bytes]:
        self.lookups.append(report_nonce)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer  # type: ignore[return-value]


def _make_ingress(
    promotion: _StubPromotion,
    resolver: _StubResolver,
    *,
    network: Optional[str] = None,
    clock: object = None,
) -> ThreatHintV2Ingress:
    return ThreatHintV2Ingress(
        promotion,  # type: ignore[arg-type]
        resolver,
        _trusted_network() if network is None else network,
        (lambda: NOW_SECONDS) if clock is None else clock,  # type: ignore[arg-type]
    )


def _accepting_ingress() -> tuple[ThreatHintV2Ingress, _StubPromotion, _StubResolver]:
    payload = _parsed()
    promotion = _StubPromotion()
    resolver = _StubResolver(payload.report_nonce)
    return _make_ingress(promotion, resolver), promotion, resolver


def _owner_only_directory() -> Path:
    path = Path(tempfile.mkdtemp(prefix="prom-hint-v2-", dir=Path.home())).resolve()
    os.chmod(path, 0o700)
    return path


@pytest.fixture
def socket_directory() -> Iterable[Path]:
    directory = _owner_only_directory()
    try:
        yield directory
    finally:
        shutil.rmtree(directory, ignore_errors=True)


async def _roundtrip(path: Path, body: bytes, *, timeout: float = 2.0) -> bytes:
    reader, writer = await asyncio.open_unix_connection(str(path))
    try:
        writer.write(len(body).to_bytes(4, "big") + body)
        await writer.drain()
        prefix = await asyncio.wait_for(reader.readexactly(4), timeout)
        size = int.from_bytes(prefix, "big")
        assert 0 < size <= MAX_V2_INGRESS_ACK_BYTES
        return await asyncio.wait_for(reader.readexactly(size), timeout)
    finally:
        writer.close()
        await writer.wait_closed()


# --- Boundary ordering: invalid transport reaches neither resolver nor promotion


def test_invalid_transport_never_reaches_resolver_or_promotion() -> None:
    promotion = _StubPromotion()
    resolver = _StubResolver(b"\x00" * 32)
    ingress = _make_ingress(promotion, resolver)

    empty = ingress.process(b"")
    assert empty.status == "rejected"
    assert empty.payload_digest == "0" * 64

    for bad_wire in (
        b"PHT2",
        b"XXXX" + _valid_wire()[4:],
        _valid_wire()[:-1],
        _valid_wire() + b"\x00",
    ):
        ack = ingress.process(bad_wire)
        assert ack.status == "rejected"
        assert ack.payload_digest == hashlib.sha256(bad_wire).hexdigest()

    assert resolver.lookups == []
    assert promotion.calls == []


def test_oversize_and_non_bytes_input_reject_with_unbound_zero_digest() -> None:
    promotion = _StubPromotion()
    resolver = _StubResolver(b"\x00" * 32)
    ingress = _make_ingress(promotion, resolver)

    oversized = ingress.process(b"P" * (MAX_TRANSPORT_PAYLOAD_BYTES + 1))
    assert oversized.status == "rejected"
    assert oversized.payload_digest == "0" * 64
    non_bytes = ingress.process(bytearray(_valid_wire()))  # type: ignore[arg-type]
    assert non_bytes.status == "rejected"
    assert non_bytes.payload_digest == "0" * 64

    assert resolver.lookups == []
    assert promotion.calls == []


def test_untrusted_network_never_reaches_resolver_or_promotion() -> None:
    promotion = _StubPromotion()
    resolver = _StubResolver(b"\x00" * 32)
    ingress = _make_ingress(promotion, resolver, network="othernet-1")

    ack = ingress.process(_valid_wire())
    assert ack.status == "rejected"
    assert ack.payload_digest == hashlib.sha256(_valid_wire()).hexdigest()
    assert resolver.lookups == []
    assert promotion.calls == []


# --- Session resolution: the payload nonce is only an untrusted lookup key


def test_unknown_session_rejects_without_promotion() -> None:
    promotion = _StubPromotion()
    resolver = _StubResolver(None)
    ingress = _make_ingress(promotion, resolver)

    ack = ingress.process(_valid_wire())
    assert ack.status == "rejected"
    assert resolver.lookups == [_parsed().report_nonce]
    assert promotion.calls == []


def test_mismatched_resolved_nonce_rejects_without_promotion() -> None:
    payload = _parsed()
    mismatched = bytes([payload.report_nonce[0] ^ 0x01]) + payload.report_nonce[1:]
    promotion = _StubPromotion()
    resolver = _StubResolver(mismatched)
    ingress = _make_ingress(promotion, resolver)

    ack = ingress.process(_valid_wire())
    assert ack.status == "rejected"
    assert resolver.lookups == [payload.report_nonce]
    assert promotion.calls == []


def test_malformed_resolver_answers_reject_without_promotion() -> None:
    payload = _parsed()
    for bad_answer in (
        payload.report_nonce.hex(),
        payload.report_nonce[:-1],
        payload.report_nonce + b"\x00",
        bytearray(payload.report_nonce),
        42,
    ):
        promotion = _StubPromotion()
        resolver = _StubResolver(bad_answer)
        ingress = _make_ingress(promotion, resolver)
        ack = ingress.process(_valid_wire())
        assert ack.status == "rejected"
        assert promotion.calls == []


def test_resolver_failure_maps_to_busy_without_promotion() -> None:
    promotion = _StubPromotion()
    resolver = _StubResolver(RuntimeError("trusted session store down"))
    ingress = _make_ingress(promotion, resolver)

    ack = ingress.process(_valid_wire())
    assert ack.status == "busy"
    assert ack.payload_digest == ""
    assert promotion.calls == []


# --- Trusted clock: current time comes only from the injected callable


def test_unusable_trusted_clock_maps_to_busy_without_promotion() -> None:
    for bad_clock in (
        lambda: 0,
        lambda: -1,
        lambda: (1 << 64),
        lambda: True,
        lambda: "1800000000",
    ):
        promotion = _StubPromotion()
        resolver = _StubResolver(_parsed().report_nonce)
        ingress = _make_ingress(promotion, resolver, clock=bad_clock)
        ack = ingress.process(_valid_wire())
        assert ack.status == "busy"
        assert promotion.calls == []

    def _exploding_clock() -> int:
        raise RuntimeError("trusted clock unavailable")

    promotion = _StubPromotion()
    resolver = _StubResolver(_parsed().report_nonce)
    ingress = _make_ingress(promotion, resolver, clock=_exploding_clock)
    assert ingress.process(_valid_wire()).status == "busy"
    assert promotion.calls == []


# --- Promotion: exact wires, resolved nonce, trusted time; stable status mapping


def test_accepted_promotion_receives_exact_wires_and_trusted_context() -> None:
    ingress, promotion, resolver = _accepting_ingress()
    payload = _parsed()

    ack = ingress.process(_valid_wire())
    assert ack.status == "accepted"
    assert ack.payload_digest == hashlib.sha256(_valid_wire()).hexdigest()
    assert resolver.lookups == [payload.report_nonce]
    assert promotion.calls == [
        (
            payload.envelope_wire,
            payload.bundle_wire,
            payload.approval_wire,
            payload.report_nonce,
            NOW_SECONDS,
        )
    ]

    ack_wire = ack.to_wire()
    assert json.loads(ack_wire.decode("ascii")) == {
        "payload_digest": hashlib.sha256(_valid_wire()).hexdigest(),
        "protocol_version": THREAT_HINT_V2_PROTOCOL_VERSION,
        "status": "accepted",
    }
    # The acknowledgement must not leak nested wires, the nonce, or approval.
    assert payload.report_nonce.hex() not in ack_wire.decode("ascii")
    assert payload.approval_wire[:16].hex() not in ack_wire.hex()


def test_busy_maps_busy_replay_and_invalid_map_rejected() -> None:
    outcomes = (
        (ThreatHintV2PromotionBusyError(), "busy"),
        (ThreatHintV2PromotionUnavailableError(), "busy"),
        (ThreatHintV2PromotionReplayError(), "rejected"),
        (ThreatHintV2PromotionError(), "rejected"),
    )
    for failure, expected in outcomes:
        promotion = _StubPromotion(failure)
        resolver = _StubResolver(_parsed().report_nonce)
        ingress = _make_ingress(promotion, resolver)
        ack = ingress.process(_valid_wire())
        assert ack.status == expected
        assert len(promotion.calls) == 1
        if expected == "busy":
            assert ack.payload_digest == ""
        else:
            assert ack.payload_digest == hashlib.sha256(_valid_wire()).hexdigest()


def test_unexpected_promotion_failure_maps_to_busy_without_leaking() -> None:
    promotion = _StubPromotion(RuntimeError("nonce=deadbeef approval=raw"))
    resolver = _StubResolver(_parsed().report_nonce)
    ingress = _make_ingress(promotion, resolver)

    ack = ingress.process(_valid_wire())
    assert ack.status == "busy"
    wire_text = ack.to_wire().decode("ascii")
    assert "deadbeef" not in wire_text
    assert "raw" not in wire_text


# --- Canonical acknowledgement framing


def test_ack_round_trip_and_canonical_encoding() -> None:
    digest = hashlib.sha256(_valid_wire()).hexdigest()
    for status in ("accepted", "rejected"):
        ack = ThreatHintV2IngressAck(status, digest)  # type: ignore[arg-type]
        assert ThreatHintV2IngressAck.from_wire(ack.to_wire()) == ack
    busy = ThreatHintV2IngressAck("busy", "")
    assert ThreatHintV2IngressAck.from_wire(busy.to_wire()) == busy

    expected = (
        b'{"payload_digest":"'
        + digest.encode("ascii")
        + b'","protocol_version":2,"status":"accepted"}'
    )
    assert ThreatHintV2IngressAck("accepted", digest).to_wire() == expected


def test_ack_rejects_adversarial_wires() -> None:
    digest = hashlib.sha256(_valid_wire()).hexdigest()
    base = json.loads(ThreatHintV2IngressAck("accepted", digest).to_wire())

    def _wire_of(payload: dict) -> bytes:
        return json.dumps(payload, separators=(",", ":")).encode("ascii")

    bad_wires = [
        _wire_of({**base, "protocol_version": 1}),
        _wire_of({**base, "status": "duplicate"}),
        _wire_of({**base, "status": "accepted", "payload_digest": digest.upper()}),
        _wire_of({**base, "status": "busy"}),
        _wire_of({**base, "report_nonce": "ab" * 32}),
        _wire_of({**base, "approval_wire": "deadbeef"}),
        _wire_of({key: base[key] for key in ("payload_digest", "status")}),
        b'{"status":"accepted","protocol_version":2,"payload_digest":"'
        + digest.encode()
        + b'"}',
        b"not json",
        b"",
    ]
    for bad_wire in bad_wires:
        with pytest.raises(ThreatHintV2IngressError):
            ThreatHintV2IngressAck.from_wire(bad_wire)

    with pytest.raises(ThreatHintV2IngressError):
        ThreatHintV2IngressAck("busy", digest).to_wire()
    with pytest.raises(ThreatHintV2IngressError):
        ThreatHintV2IngressAck("accepted", "").to_wire()


def test_constructor_rejects_untrusted_wiring() -> None:
    payload = _parsed()
    promotion = _StubPromotion()
    resolver = _StubResolver(payload.report_nonce)
    with pytest.raises(ThreatHintV2IngressError):
        _make_ingress(promotion, resolver, network="BAD NETWORK!")
    with pytest.raises(ThreatHintV2IngressError):
        _make_ingress(promotion, resolver, clock="not-callable")
    with pytest.raises(ThreatHintV2IngressError):
        _make_ingress(object(), resolver)  # type: ignore[arg-type]
    with pytest.raises(ThreatHintV2IngressError):
        _make_ingress(promotion, object())  # type: ignore[arg-type]


def test_bsd_peer_credentials_compare_only_the_effective_uid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _PeerSocket:
        @staticmethod
        def getpeereid() -> tuple[int, int]:
            return (os.geteuid(), 42)

    monkeypatch.setattr(ingress_module.os, "name", "posix")
    assert ingress_module._has_same_euid_peer(_PeerSocket())  # type: ignore[arg-type]  # pylint: disable=protected-access


# --- Owner-only single-frame AF_UNIX server


@pytest.mark.asyncio
async def test_server_roundtrip_promotes_and_returns_canonical_ack(
    socket_directory: Path,
) -> None:
    ingress, promotion, _resolver = _accepting_ingress()
    socket_path = socket_directory / "v2-ingress.sock"
    server = ThreatHintV2IngressServer(socket_path, ingress)
    await server.start()
    try:
        assert stat.S_ISSOCK(socket_path.lstat().st_mode)
        assert socket_path.stat().st_mode & 0o777 == 0o600

        ack_wire = await _roundtrip(socket_path, _valid_wire())
        ack = ThreatHintV2IngressAck.from_wire(ack_wire)
        assert ack.status == "accepted"
        assert ack.payload_digest == hashlib.sha256(_valid_wire()).hexdigest()
        assert len(promotion.calls) == 1
    finally:
        await server.close()
    assert not socket_path.exists()


@pytest.mark.asyncio
async def test_server_rejects_invalid_frame_without_touching_promotion(
    socket_directory: Path,
) -> None:
    ingress, promotion, resolver = _accepting_ingress()
    socket_path = socket_directory / "v2-ingress.sock"
    async with ThreatHintV2IngressServer(socket_path, ingress):
        garbage = b"\xff" * 64
        ack_wire = await _roundtrip(socket_path, garbage)
        ack = ThreatHintV2IngressAck.from_wire(ack_wire)
        assert ack.status == "rejected"
        assert ack.payload_digest == hashlib.sha256(garbage).hexdigest()
        assert resolver.lookups == []
        assert promotion.calls == []


@pytest.mark.asyncio
async def test_server_rejects_oversized_frame_with_unbound_digest(
    socket_directory: Path,
) -> None:
    ingress, promotion, resolver = _accepting_ingress()
    socket_path = socket_directory / "v2-ingress.sock"
    async with ThreatHintV2IngressServer(socket_path, ingress):
        reader, writer = await asyncio.open_unix_connection(str(socket_path))
        try:
            writer.write((MAX_TRANSPORT_PAYLOAD_BYTES + 1).to_bytes(4, "big"))
            await writer.drain()
            prefix = await asyncio.wait_for(reader.readexactly(4), 2.0)
            size = int.from_bytes(prefix, "big")
            ack = ThreatHintV2IngressAck.from_wire(
                await asyncio.wait_for(reader.readexactly(size), 2.0)
            )
            assert ack.status == "rejected"
            assert ack.payload_digest == "0" * 64
        finally:
            writer.close()
            await writer.wait_closed()
        assert resolver.lookups == []
        assert promotion.calls == []


@pytest.mark.asyncio
async def test_server_idle_connection_is_closed_without_ack(
    socket_directory: Path,
) -> None:
    ingress, _promotion, _resolver = _accepting_ingress()
    socket_path = socket_directory / "v2-ingress.sock"
    async with ThreatHintV2IngressServer(socket_path, ingress, io_timeout_seconds=0.1):
        reader, writer = await asyncio.open_unix_connection(str(socket_path))
        try:
            with pytest.raises((asyncio.IncompleteReadError, ConnectionError)):
                await asyncio.wait_for(reader.readexactly(4), 2.0)
        finally:
            writer.close()
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_server_overload_returns_unbound_busy(
    socket_directory: Path,
) -> None:
    payload = _parsed()
    gate = threading.Event()

    class _BlockingPromotion(_StubPromotion):
        def promote(self, *args: object, **_kwargs: object) -> object:
            self.calls.append(args)  # type: ignore[arg-type]
            gate.wait(5.0)
            return object()

    promotion = _BlockingPromotion()
    ingress = _make_ingress(promotion, _StubResolver(payload.report_nonce))
    socket_path = socket_directory / "v2-ingress.sock"
    server = ThreatHintV2IngressServer(socket_path, ingress, max_connections=1)
    await server.start()
    try:
        first_reader, first_writer = await asyncio.open_unix_connection(
            str(socket_path)
        )
        first_writer.write(len(_valid_wire()).to_bytes(4, "big") + _valid_wire())
        await first_writer.drain()
        await asyncio.sleep(0.2)

        busy_wire = await _roundtrip(socket_path, _valid_wire())
        busy = ThreatHintV2IngressAck.from_wire(busy_wire)
        assert busy.status == "busy"
        assert busy.payload_digest == ""

        gate.set()
        prefix = await asyncio.wait_for(first_reader.readexactly(4), 2.0)
        size = int.from_bytes(prefix, "big")
        first_ack = ThreatHintV2IngressAck.from_wire(
            await asyncio.wait_for(first_reader.readexactly(size), 2.0)
        )
        assert first_ack.status == "accepted"
        first_writer.close()
        await first_writer.wait_closed()
    finally:
        gate.set()
        await server.close()


@pytest.mark.asyncio
async def test_server_close_waits_for_started_promotion_work(
    socket_directory: Path,
) -> None:
    payload = _parsed()
    started = threading.Event()
    release = threading.Event()
    completed = threading.Event()

    class _BlockingPromotion(_StubPromotion):
        def promote(self, *args: object, **_kwargs: object) -> object:
            self.calls.append(args)  # type: ignore[arg-type]
            started.set()
            release.wait(5.0)
            completed.set()
            return object()

    promotion = _BlockingPromotion()
    ingress = _make_ingress(promotion, _StubResolver(payload.report_nonce))
    socket_path = socket_directory / "v2-ingress.sock"
    server = ThreatHintV2IngressServer(socket_path, ingress, max_connections=1)
    await server.start()
    _reader, writer = await asyncio.open_unix_connection(str(socket_path))
    writer.write(len(_valid_wire()).to_bytes(4, "big") + _valid_wire())
    await writer.drain()
    assert await asyncio.to_thread(started.wait, 2.0)

    close_task = asyncio.create_task(server.close())
    await asyncio.sleep(0.1)
    assert not close_task.done()
    assert not completed.is_set()

    release.set()
    await asyncio.wait_for(close_task, 2.0)
    assert completed.is_set()
    assert not socket_path.exists()
    writer.close()
    await writer.wait_closed()


def test_server_rejects_unsafe_socket_paths() -> None:
    ingress, _promotion, _resolver = _accepting_ingress()

    world_readable = _owner_only_directory()
    try:
        os.chmod(world_readable, 0o755)
        with pytest.raises(ThreatHintV2IngressError, match="owner-controlled"):
            ThreatHintV2IngressServer(world_readable / "v2.sock", ingress)
    finally:
        shutil.rmtree(world_readable, ignore_errors=True)

    directory = _owner_only_directory()
    try:
        existing = directory / "existing.sock"
        existing.write_bytes(b"stale")
        with pytest.raises(ThreatHintV2IngressError, match="already exists"):
            ThreatHintV2IngressServer(existing, ingress)
        with pytest.raises(ThreatHintV2IngressError, match="absolute"):
            ThreatHintV2IngressServer(Path("relative.sock"), ingress)
        with pytest.raises(ThreatHintV2IngressError, match="max_connections"):
            ThreatHintV2IngressServer(directory / "v2.sock", ingress, max_connections=0)
        with pytest.raises(ThreatHintV2IngressError, match="io timeout"):
            ThreatHintV2IngressServer(
                directory / "v2.sock", ingress, io_timeout_seconds=0
            )
    finally:
        shutil.rmtree(directory, ignore_errors=True)


@pytest.mark.asyncio
async def test_server_restart_and_foreign_socket_survive_cleanup(
    socket_directory: Path,
) -> None:
    ingress, _promotion, _resolver = _accepting_ingress()
    socket_path = socket_directory / "v2-ingress.sock"
    server = ThreatHintV2IngressServer(socket_path, ingress)
    await server.start()
    with pytest.raises(ThreatHintV2IngressError, match="already running"):
        await server.start()
    await server.close()
    await server.close()
    assert not socket_path.exists()

    # A foreign replacement at the same path must never be unlinked.
    foreign = socket_path
    foreign.write_bytes(b"foreign")
    await server.close()
    assert foreign.read_bytes() == b"foreign"
