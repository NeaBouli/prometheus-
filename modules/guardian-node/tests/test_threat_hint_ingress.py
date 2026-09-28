"""Security and lifecycle tests for the owner-only ThreatHint ingress."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import tempfile
import threading
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from jaeger.threat_hint_ingress import (
    CanonicalThreatHint,
    Kip16Groth16Verifier,
    MAX_HINT_AGE_SECONDS,
    MAX_THREAT_HINT_WIRE_BYTES,
    ThreatHintIngress,
    ThreatHintIngressAck,
    ThreatHintIngressError,
    ThreatHintIngressServer,
    ThreatHintReplayLedger,
    ThreatProofContext,
    ThreatProofVerifierUnavailable,
    UnavailableThreatProofVerifier,
    submit_to_threat_hint_ingress,
)

NOW_SECONDS = 1_800_000_000
CONTEXT = ThreatProofContext("testnet-10")


def _bound_proof(hint: CanonicalThreatHint, context: ThreatProofContext) -> str:
    statement = "|".join(
        (
            context.verification_domain,
            context.network_id,
            str(hint.schema_version),
            hint.threat_hash,
            str(hint.confidence_bps),
            hint.indicator_type,
            hint.proof_system,
            hint.report_nonce,
            str(hint.observed_at),
        )
    )
    return hashlib.sha256(statement.encode("ascii")).hexdigest()


def make_hint(**changes: object) -> CanonicalThreatHint:
    base = CanonicalThreatHint(
        schema_version=1,
        threat_hash="11" * 32,
        confidence_bps=8_501,
        indicator_type="behavior",
        proof_system="groth16_kip16_v1",
        proof="00",
        report_nonce="22" * 32,
        observed_at=NOW_SECONDS,
    )
    changed = replace(base, **changes)
    if "proof" not in changes:
        changed = replace(changed, proof=_bound_proof(changed, CONTEXT))
    return changed


class BindingTestVerifier:
    """Test-only verifier that proves every public field and trusted context bind."""

    def verify(
        self,
        envelope: CanonicalThreatHint,
        canonical_wire: bytes,
        context: ThreatProofContext,
    ) -> bool:
        return envelope.to_wire() == canonical_wire and envelope.proof == _bound_proof(
            envelope, context
        )


def owner_only_directory() -> Path:
    path = Path(tempfile.mkdtemp(prefix="prom-hint-", dir=Path.home())).resolve()
    os.chmod(path, 0o700)
    return path


def verifier_fixture(
    directory: Path, exit_code: int, *, delay: bool = False
) -> tuple[Path, Path]:
    binary = directory / f"verifier-{exit_code}"
    wait = "/bin/sleep 1\n" if delay else ""
    binary.write_text(f"#!/bin/sh\n{wait}/bin/cat >/dev/null\nexit {exit_code}\n")
    os.chmod(binary, 0o700)
    manifest = directory / "relation-manifest.json"
    manifest.write_bytes(b"{}")
    os.chmod(manifest, 0o600)
    return binary, manifest


def test_canonical_schema_rejects_noncanonical_and_duplicate_fields() -> None:
    hint = make_hint()
    wire = hint.to_wire()
    assert CanonicalThreatHint.from_wire(wire) == hint
    with pytest.raises(ThreatHintIngressError, match="canonical"):
        CanonicalThreatHint.from_wire(wire + b" ")
    duplicated = wire.replace(
        b'"schema_version":1', b'"schema_version":1,"schema_version":1', 1
    )
    with pytest.raises(ThreatHintIngressError, match="strict JSON"):
        CanonicalThreatHint.from_wire(duplicated)
    with pytest.raises(ThreatHintIngressError, match="hash"):
        CanonicalThreatHint.from_wire(replace(hint, threat_hash="AA" * 32).to_wire())


@pytest.mark.asyncio
async def test_unavailable_verifier_is_busy_and_stub_is_rejected() -> None:
    directory = owner_only_directory()
    try:
        ledger = ThreatHintReplayLedger(directory / "replay.sqlite3")
        unavailable = await ThreatHintIngress(
            ledger, UnavailableThreatProofVerifier(), CONTEXT
        ).process(make_hint().to_wire(), NOW_SECONDS)
        stub = make_hint(proof_system="development_stub_v1")
        rejected = await ThreatHintIngress(
            ledger, BindingTestVerifier(), CONTEXT
        ).process(stub.to_wire(), NOW_SECONDS)
        assert unavailable == ThreatHintIngressAck("busy", "")
        assert rejected.status == "rejected"
        assert ledger.pending_jobs(1) == []
    finally:
        shutil.rmtree(directory)


def test_kip16_adapter_maps_closed_exit_codes() -> None:
    directory = owner_only_directory().resolve()
    try:
        for exit_code, expected in ((0, True), (1, False)):
            binary, manifest = verifier_fixture(directory, exit_code)
            verifier = Kip16Groth16Verifier(binary, manifest, "11" * 32)
            hint = make_hint()
            assert verifier.verify(hint, hint.to_wire(), CONTEXT) is expected
            binary.unlink()
        binary, manifest = verifier_fixture(directory, 3)
        verifier = Kip16Groth16Verifier(binary, manifest, "11" * 32)
        with pytest.raises(ThreatProofVerifierUnavailable):
            verifier.verify(make_hint(), make_hint().to_wire(), CONTEXT)
    finally:
        shutil.rmtree(directory)


def test_kip16_adapter_timeout_and_permissions_fail_closed() -> None:
    directory = owner_only_directory().resolve()
    try:
        binary, manifest = verifier_fixture(directory, 0, delay=True)
        verifier = Kip16Groth16Verifier(
            binary, manifest, "11" * 32, timeout_seconds=0.01
        )
        hint = make_hint()
        with pytest.raises(ThreatProofVerifierUnavailable):
            verifier.verify(hint, hint.to_wire(), CONTEXT)
        binary.chmod(binary.stat().st_mode | stat.S_IWOTH)
        with pytest.raises(ThreatProofVerifierUnavailable):
            verifier.verify(hint, hint.to_wire(), CONTEXT)
        with pytest.raises(ThreatHintIngressError, match="not trusted"):
            Kip16Groth16Verifier(binary, manifest, "11" * 32)
        os.chmod(binary, 0o700)
        os.chmod(manifest, 0o644)
        with pytest.raises(ThreatHintIngressError, match="owner-only"):
            Kip16Groth16Verifier(binary, manifest, "11" * 32)
    finally:
        shutil.rmtree(directory)


def test_kip16_adapter_rejects_untrusted_binary_ancestor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = owner_only_directory().resolve()
    try:
        binary, manifest = verifier_fixture(directory, 0)
        original_stat = Path.stat

        def stat_with_untrusted_owner(path: Path, *args: object, **kwargs: object):
            result = original_stat(path, *args, **kwargs)
            if path == directory:
                return SimpleNamespace(
                    st_mode=result.st_mode,
                    st_uid=os.getuid() + 1,
                )
            return result

        monkeypatch.setattr(Path, "stat", stat_with_untrusted_owner)
        with pytest.raises(ThreatHintIngressError, match="parent is not trusted"):
            Kip16Groth16Verifier(binary, manifest, "11" * 32)
    finally:
        shutil.rmtree(directory)


@pytest.mark.asyncio
async def test_verified_admission_and_outbox_survive_restart() -> None:
    directory = owner_only_directory()
    try:
        ledger_path = directory / "replay.sqlite3"
        wire = make_hint().to_wire()
        ingress = ThreatHintIngress(
            ThreatHintReplayLedger(ledger_path), BindingTestVerifier(), CONTEXT
        )
        accepted, duplicate = await asyncio.gather(
            ingress.process(wire, NOW_SECONDS),
            ingress.process(wire, NOW_SECONDS),
        )
        assert {accepted.status, duplicate.status} == {"accepted", "duplicate"}

        restarted = ThreatHintReplayLedger(ledger_path)
        jobs = restarted.pending_jobs(8)
        assert len(jobs) == 1
        assert jobs[0].canonical_wire == wire
        assert jobs[0].network_id == CONTEXT.network_id
        retry = await ThreatHintIngress(
            restarted, BindingTestVerifier(), CONTEXT
        ).process(wire, NOW_SECONDS)
        assert retry.status == "duplicate"
        assert len(restarted.pending_jobs(8)) == 1
    finally:
        shutil.rmtree(directory)


@pytest.mark.asyncio
async def test_test_verifier_binds_fields_and_trusted_network() -> None:
    directory = owner_only_directory()
    try:
        original = make_hint()
        tampered = replace(original, confidence_bps=original.confidence_bps - 1)
        wrong_network = ThreatProofContext("testnet-11")
        ledger = ThreatHintReplayLedger(directory / "replay.sqlite3")
        assert (
            await ThreatHintIngress(ledger, BindingTestVerifier(), CONTEXT).process(
                tampered.to_wire(), NOW_SECONDS
            )
        ).status == "rejected"
        assert (
            await ThreatHintIngress(
                ledger, BindingTestVerifier(), wrong_network
            ).process(original.to_wire(), NOW_SECONDS)
        ).status == "rejected"
        assert ledger.pending_jobs(8) == []
    finally:
        shutil.rmtree(directory)


@pytest.mark.asyncio
async def test_conflicts_freshness_and_clock_rollback_fail_closed() -> None:
    directory = owner_only_directory()
    try:
        ledger = ThreatHintReplayLedger(directory / "replay.sqlite3")
        ingress = ThreatHintIngress(ledger, BindingTestVerifier(), CONTEXT)
        assert (
            await ingress.process(make_hint().to_wire(), NOW_SECONDS)
        ).status == "accepted"
        cases = (
            make_hint(threat_hash="33" * 32),
            make_hint(report_nonce="44" * 32),
            make_hint(
                report_nonce="55" * 32,
                threat_hash="55" * 32,
                observed_at=NOW_SECONDS - MAX_HINT_AGE_SECONDS - 1,
            ),
            make_hint(
                report_nonce="66" * 32,
                threat_hash="66" * 32,
                observed_at=NOW_SECONDS + 31,
            ),
        )
        for hint in cases:
            assert (
                await ingress.process(hint.to_wire(), NOW_SECONDS)
            ).status == "rejected"
        rollback = make_hint(report_nonce="77" * 32, threat_hash="77" * 32)
        assert (
            await ingress.process(rollback.to_wire(), NOW_SECONDS - 1)
        ).status == "rejected"
        assert len(ledger.pending_jobs(8)) == 1
    finally:
        shutil.rmtree(directory)


@pytest.mark.asyncio
async def test_sqlite_lock_returns_busy_without_consuming_replay() -> None:
    directory = owner_only_directory()
    try:
        ledger_path = directory / "replay.sqlite3"
        ledger = ThreatHintReplayLedger(ledger_path)
        lock = sqlite3.connect(ledger_path, isolation_level=None)
        lock.execute("BEGIN EXCLUSIVE")
        wire = make_hint().to_wire()
        busy = await ThreatHintIngress(ledger, BindingTestVerifier(), CONTEXT).process(
            wire, NOW_SECONDS
        )
        assert busy == ThreatHintIngressAck("busy", "")
        lock.rollback()
        lock.close()
        accepted = await ThreatHintIngress(
            ledger, BindingTestVerifier(), CONTEXT
        ).process(wire, NOW_SECONDS)
        assert accepted.status == "accepted"
    finally:
        shutil.rmtree(directory)


def test_outbox_batches_are_bounded_and_delivery_is_idempotent() -> None:
    directory = owner_only_directory()
    try:
        ledger = ThreatHintReplayLedger(directory / "replay.sqlite3")
        for index in range(3):
            hint = make_hint(
                threat_hash=f"{index + 10:064x}",
                report_nonce=f"{index + 20:064x}",
            )
            assert (
                ledger.admit(hint, hint.to_wire(), CONTEXT, NOW_SECONDS) == "accepted"
            )
        batch = ledger.pending_jobs(2)
        assert len(batch) == 2
        ledger.mark_delivered(batch[0].payload_digest, NOW_SECONDS)
        ledger.mark_delivered(batch[0].payload_digest, NOW_SECONDS + 1)
        assert len(ledger.pending_jobs(8)) == 2
        with pytest.raises(ThreatHintIngressError, match="limit"):
            ledger.pending_jobs(257)
    finally:
        shutil.rmtree(directory)


@pytest.mark.asyncio
async def test_owner_only_server_round_trip_and_response_loss_retry() -> None:
    directory = owner_only_directory()
    socket_path = directory / "threat-hint.sock"
    ledger = ThreatHintReplayLedger(directory / "replay.sqlite3")
    server = ThreatHintIngressServer(
        socket_path,
        ThreatHintIngress(ledger, BindingTestVerifier(), CONTEXT),
        now_seconds=lambda: NOW_SECONDS,
    )
    try:
        await server.start()
        assert socket_path.stat().st_mode & 0o777 == 0o600
        wire = make_hint().to_wire()
        reader, writer = await asyncio.open_unix_connection(socket_path)
        del reader
        writer.write(len(wire).to_bytes(4, "big") + wire)
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        for _ in range(50):
            if ledger.pending_jobs(1):
                break
            await asyncio.sleep(0.01)
        retry = await submit_to_threat_hint_ingress(socket_path, wire)
        assert retry.status == "duplicate"
        assert len(ledger.pending_jobs(8)) == 1
    finally:
        await server.close()
        shutil.rmtree(directory)


@pytest.mark.asyncio
async def test_server_rejects_oversized_prefix_without_body_allocation() -> None:
    directory = owner_only_directory()
    socket_path = directory / "threat-hint.sock"
    server = ThreatHintIngressServer(
        socket_path,
        ThreatHintIngress(
            ThreatHintReplayLedger(directory / "replay.sqlite3"),
            UnavailableThreatProofVerifier(),
            CONTEXT,
        ),
        now_seconds=lambda: NOW_SECONDS,
    )
    try:
        await server.start()
        reader, writer = await asyncio.open_unix_connection(socket_path)
        writer.write((MAX_THREAT_HINT_WIRE_BYTES + 1).to_bytes(4, "big"))
        await writer.drain()
        size = int.from_bytes(await reader.readexactly(4), "big")
        assert (
            ThreatHintIngressAck.from_wire(await reader.readexactly(size)).status
            == "rejected"
        )
        writer.close()
        await writer.wait_closed()
    finally:
        await server.close()
        shutil.rmtree(directory)


@pytest.mark.asyncio
async def test_timed_out_verifier_retains_connection_permit() -> None:
    class BlockingVerifier:
        def __init__(self) -> None:
            self.started = threading.Event()
            self.release = threading.Event()

        def verify(
            self,
            envelope: CanonicalThreatHint,
            canonical_wire: bytes,
            context: ThreatProofContext,
        ) -> bool:
            del envelope, canonical_wire, context
            self.started.set()
            self.release.wait()
            return True

    directory = owner_only_directory()
    socket_path = directory / "threat-hint.sock"
    verifier = BlockingVerifier()
    server = ThreatHintIngressServer(
        socket_path,
        ThreatHintIngress(
            ThreatHintReplayLedger(directory / "replay.sqlite3"),
            verifier,
            CONTEXT,
        ),
        now_seconds=lambda: NOW_SECONDS,
        max_connections=1,
        io_timeout_seconds=0.01,
    )
    try:
        await server.start()
        with pytest.raises((asyncio.IncompleteReadError, TimeoutError)):
            await submit_to_threat_hint_ingress(
                socket_path, make_hint().to_wire(), timeout_seconds=0.05
            )
        assert await asyncio.to_thread(verifier.started.wait, 0.5)
        assert await submit_to_threat_hint_ingress(
            socket_path, make_hint().to_wire()
        ) == ThreatHintIngressAck("busy", "")
    finally:
        verifier.release.set()
        await server.close()
        shutil.rmtree(directory)


@pytest.mark.asyncio
async def test_shutdown_cancels_blocked_verifier_before_admission() -> None:
    class BlockingVerifier:
        def __init__(self) -> None:
            self.started = threading.Event()
            self.release = threading.Event()

        def verify(
            self,
            envelope: CanonicalThreatHint,
            canonical_wire: bytes,
            context: ThreatProofContext,
        ) -> bool:
            del envelope, canonical_wire, context
            self.started.set()
            self.release.wait()
            return True

    directory = owner_only_directory()
    socket_path = directory / "threat-hint.sock"
    ledger = ThreatHintReplayLedger(directory / "replay.sqlite3")
    verifier = BlockingVerifier()
    server = ThreatHintIngressServer(
        socket_path,
        ThreatHintIngress(ledger, verifier, CONTEXT),
        now_seconds=lambda: NOW_SECONDS,
        io_timeout_seconds=0.01,
    )
    client: asyncio.Task[ThreatHintIngressAck] | None = None
    try:
        await server.start()
        client = asyncio.create_task(
            submit_to_threat_hint_ingress(socket_path, make_hint().to_wire())
        )
        assert await asyncio.to_thread(verifier.started.wait, 0.5)
        await server.close()
        verifier.release.set()
        await asyncio.sleep(0.05)
        assert ledger.pending_jobs(8) == []
    finally:
        verifier.release.set()
        if client is not None:
            client.cancel()
            await asyncio.gather(client, return_exceptions=True)
        await server.close()
        shutil.rmtree(directory)


def test_ack_context_and_paths_are_strict() -> None:
    ack = ThreatHintIngressAck("accepted", "aa" * 32)
    assert ThreatHintIngressAck.from_wire(ack.to_wire()) == ack
    payload = json.loads(ack.to_wire())
    payload["extra"] = True
    with pytest.raises(ThreatHintIngressError, match="schema"):
        ThreatHintIngressAck.from_wire(
            json.dumps(payload, separators=(",", ":")).encode("ascii")
        )
    with pytest.raises(ThreatHintIngressError, match="context"):
        ThreatProofContext("../mainnet")

    directory = owner_only_directory()
    try:
        unsafe = directory / "unsafe"
        unsafe.mkdir(mode=0o755)
        with pytest.raises(ThreatHintIngressError, match="owner-only"):
            ThreatHintReplayLedger(unsafe / "replay.sqlite3")
        regular = directory / "existing.sock"
        regular.write_text("do not replace", encoding="ascii")
        with pytest.raises(ThreatHintIngressError, match="already exists"):
            ThreatHintIngressServer(
                regular,
                ThreatHintIngress(
                    ThreatHintReplayLedger(directory / "replay.sqlite3"),
                    UnavailableThreatProofVerifier(),
                    CONTEXT,
                ),
                now_seconds=lambda: NOW_SECONDS,
            )
    finally:
        shutil.rmtree(directory)


def test_kip16_adapter_rejects_executable_replaced_after_preflight() -> None:
    directory = owner_only_directory().resolve()
    try:
        binary, manifest = verifier_fixture(directory, 0)
        verifier = Kip16Groth16Verifier(binary, manifest, "11" * 32)
        hint = make_hint()
        assert verifier.verify(hint, hint.to_wire(), CONTEXT) is True
        marker = directory / "replacement-ran"
        replacement = directory / "replacement"
        replacement.write_text(f"#!/bin/sh\n/usr/bin/touch {marker}\nexit 0\n")
        os.chmod(replacement, 0o700)
        os.replace(replacement, binary)
        with pytest.raises(ThreatProofVerifierUnavailable) as renamed:
            verifier.verify(hint, hint.to_wire(), CONTEXT)
        binary.write_text(f"#!/bin/sh\n/usr/bin/touch {marker}\nexit 1\n")
        os.chmod(binary, 0o700)
        with pytest.raises(ThreatProofVerifierUnavailable) as rewritten:
            verifier.verify(hint, hint.to_wire(), CONTEXT)
        assert not marker.exists()
        for failure in (renamed.value, rewritten.value):
            assert str(failure) == "approved Groth16 verifier unavailable"
            assert str(directory) not in str(failure.__cause__)
    finally:
        shutil.rmtree(directory)


@pytest.mark.asyncio
async def test_replaced_executable_is_busy_without_ledger_mutation() -> None:
    directory = owner_only_directory().resolve()
    try:
        binary, manifest = verifier_fixture(directory, 0)
        verifier = Kip16Groth16Verifier(binary, manifest, "11" * 32)
        ledger_path = directory / "replay.sqlite3"
        ledger = ThreatHintReplayLedger(ledger_path)
        before = ledger_path.read_bytes()
        binary.write_text("#!/bin/sh\n/bin/cat >/dev/null\nexit 0 \n")
        os.chmod(binary, 0o700)
        ack = await ThreatHintIngress(ledger, verifier, CONTEXT).process(
            make_hint().to_wire(), NOW_SECONDS
        )
        assert ack == ThreatHintIngressAck("busy", "")
        assert ledger.pending_jobs(1) == []
        assert ledger_path.read_bytes() == before
    finally:
        shutil.rmtree(directory)


@pytest.mark.parametrize("race", [PermissionError, ProcessLookupError])
def test_kip16_adapter_reaps_child_when_process_group_kill_races(
    monkeypatch: pytest.MonkeyPatch, race: type[OSError]
) -> None:
    import subprocess  # pylint: disable=import-outside-toplevel

    import jaeger.threat_hint_ingress as ingress  # pylint: disable=import-outside-toplevel

    directory = owner_only_directory().resolve()
    started: list[subprocess.Popen[bytes]] = []
    original_popen = subprocess.Popen

    def recording_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = original_popen(*args, **kwargs)  # type: ignore[call-overload]
        started.append(process)
        return process

    def racing_killpg(_pgid: int, _signal: int) -> None:
        raise race()

    try:
        binary, manifest = verifier_fixture(directory, 0, delay=True)
        verifier = Kip16Groth16Verifier(
            binary, manifest, "11" * 32, timeout_seconds=0.05
        )
        monkeypatch.setattr(ingress.subprocess, "Popen", recording_popen)
        monkeypatch.setattr(ingress.os, "killpg", racing_killpg)
        hint = make_hint()
        with pytest.raises(ThreatProofVerifierUnavailable) as failure:
            verifier.verify(hint, hint.to_wire(), CONTEXT)
        assert str(failure.value) == "approved Groth16 verifier unavailable"
        assert len(started) == 1
        assert started[0].poll() is not None
    finally:
        shutil.rmtree(directory)


def test_replay_ledger_rejects_symlink_and_unsafe_existing_files() -> None:
    directory = owner_only_directory()
    try:
        target = directory / "target.sqlite3"
        target.write_bytes(b"do not open")
        os.chmod(target, 0o600)
        link = directory / "link.sqlite3"
        link.symlink_to(target)
        with pytest.raises(ThreatHintIngressError) as symlinked:
            ThreatHintReplayLedger(link)
        assert str(symlinked.value) == "ThreatHint ledger must not be a symlink"
        dangling = directory / "dangling.sqlite3"
        dangling.symlink_to(directory / "missing.sqlite3")
        with pytest.raises(ThreatHintIngressError, match="must not be a symlink"):
            ThreatHintReplayLedger(dangling)
        assert not (directory / "missing.sqlite3").exists()
        assert target.read_bytes() == b"do not open"
        assert stat.S_IMODE(target.lstat().st_mode) == 0o600

        for mode in (0o400, 0o640, 0o604, 0o700, 0o2600):
            unsafe = directory / f"unsafe-{mode:o}.sqlite3"
            unsafe.write_bytes(b"unchanged")
            os.chmod(unsafe, mode)
            actual_mode = stat.S_IMODE(unsafe.lstat().st_mode)
            with pytest.raises(ThreatHintIngressError) as rejected:
                ThreatHintReplayLedger(unsafe)
            assert str(rejected.value) == "ThreatHint ledger must be owner-only"
            assert str(directory) not in str(rejected.value)
            os.chmod(unsafe, 0o600)
            assert unsafe.read_bytes() == b"unchanged"
            assert actual_mode != 0o600
        not_regular = directory / "directory.sqlite3"
        not_regular.mkdir(mode=0o700)
        with pytest.raises(ThreatHintIngressError, match="owner-only"):
            ThreatHintReplayLedger(not_regular)
        fifo = directory / "fifo.sqlite3"
        os.mkfifo(fifo, 0o600)
        with pytest.raises(ThreatHintIngressError, match="owner-only"):
            ThreatHintReplayLedger(fifo)
    finally:
        shutil.rmtree(directory)


def test_replay_ledger_requires_exact_owner_only_mode() -> None:
    directory = owner_only_directory()
    previous_umask = os.umask(0)
    try:
        created = directory / "created.sqlite3"
        ThreatHintReplayLedger(created)
        assert stat.S_IMODE(created.lstat().st_mode) == 0o600
        existing = directory / "existing.sqlite3"
        existing.touch(mode=0o600)
        os.chmod(existing, 0o600)
        ThreatHintReplayLedger(existing)
        assert stat.S_IMODE(existing.lstat().st_mode) == 0o600
    finally:
        os.umask(previous_umask)
        shutil.rmtree(directory)
