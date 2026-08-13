"""Deterministic synthetic-only ThreatHint-v2 pipeline integration gate (GH-180).

This file composes the real existing public boundaries end to end:

canonical transport bytes -> ``ThreatHintV2Ingress`` (real governed promotion,
not a stub) -> governed promotion + atomic acceptance -> schema-v5 recoverable
outbox -> ``ObservableAnalysisWorker`` with ``DeterministicSemanticDraftAnalyzer``
-> durable non-actionable semantic-draft result.

Only the canonical synthetic fixtures are reused; the session resolver is a
test-local implementation of the public resolver protocol. No production
helper was required: every boundary wires directly through its existing public
constructor. The GH-177 ``yara_semantic_quality`` module is never imported and
no worker/outbox wiring is added for it. All data is synthetic and every
injected failure uses a redaction marker that must never leak into stable
error messages.
"""

# Tests intentionally inspect the local ledger and reuse candidate fixtures;
# exact emptiness assertions stay explicit for protocol clarity, and the happy
# path keeps its full assertion sequence in one end-to-end test.
# pylint: disable=missing-function-docstring,too-many-locals
# pylint: disable=too-few-public-methods,too-many-statements
# pylint: disable=use-implicit-booleaness-not-comparison

from __future__ import annotations

import hashlib
import json
import os
import shlex
import sqlite3
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

import jaeger.observable_analysis_worker as worker_module
import jaeger.observable_approval_consumption as consumption_module
import jaeger.observable_semantic_draft as draft_module
import jaeger.threat_hint_v2_acceptance as acceptance_module
import jaeger.threat_hint_v2_governance as governance_module
import jaeger.threat_hint_v2_ingress as ingress_module
import jaeger.threat_hint_v2_preflight as preflight_module
import jaeger.threat_hint_v2_promotion as promotion_module
import jaeger.threat_hint_v2_transport as transport_module
import jaeger.threat_hint_v2_verified_preflight as verified_preflight_module
import pytest
from jaeger.observable_analysis_worker import (
    SEMANTIC_DRAFT_ANALYZER_ID,
    SEMANTIC_DRAFT_BINDING_DOMAIN,
    DeterministicSemanticDraftAnalyzer,
    ObservableAnalysisAnalyzer,
    ObservableAnalysisInput,
    ObservableAnalysisWorker,
    ObservableAnalysisWorkerError,
)
from jaeger.observable_approval_consumption import (
    SEMANTIC_DRAFT_RESULT_KIND,
    SEMANTIC_DRAFT_RESULT_SCHEMA_VERSION,
    ObservableApprovalOutboxError,
)
from jaeger.observable_semantic_draft import derive_semantic_draft
from jaeger.threat_hint_v2_ingress import ThreatHintV2Ingress
from jaeger.threat_hint_v2_statement import STATEMENT_DIGEST_DOMAIN
from jaeger.threat_hint_v2_transport import (
    LENGTH_FIELD_BYTES,
    MAX_TRANSPORT_PAYLOAD_BYTES,
    TRANSPORT_MAGIC,
    TRANSPORT_VERSION,
)
from jaeger.threat_observable import ObservableBundle
from tests.test_threat_hint_v2_acceptance import (
    _consumption_count,
    _high_water,
    _ledger_path,
)
from tests.test_threat_hint_v2_governed_promotion import (
    _authority_state,
    _governed_service,
    _schema_version,
)
from tests.test_threat_hint_v2_outbox import (
    _claim_service,
    _outbox_binding_rows,
    _outbox_rows,
    _pairing_rows,
    _result_rows,
)
from tests.test_threat_hint_v2_preflight import _Scenario

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="governed pipeline requires POSIX controls"
)

_ZERO_DIGEST = "0" * 64
_VERIFIER_OK_BODY = "/bin/cat >/dev/null\nexit 0"
_ANALYSIS_FAILURE_MARKER = "synthetic-analysis-failure-marker"
_COMPLETION_FAILURE_MARKER = "synthetic-completion-failure-marker"


class _RecordingSessionResolver:
    """Test-local trusted session resolver with one fixed active session."""

    def __init__(self, trusted_nonce: bytes) -> None:
        self._trusted_nonce = trusted_nonce
        self.lookups: List[bytes] = []

    def resolve(self, report_nonce: bytes) -> Optional[bytes]:
        self.lookups.append(report_nonce)
        return self._trusted_nonce


class _FailingAnalyzer:
    """Synthetic analyzer that always fails with a redaction marker."""

    async def analyze(self, _: ObservableAnalysisInput) -> bytes:
        raise RuntimeError(_ANALYSIS_FAILURE_MARKER)


def _transport_wire(scenario: _Scenario) -> bytes:
    """Frame the exact scenario wires as one canonical v2 transport payload."""
    return b"".join(
        (
            TRANSPORT_MAGIC,
            bytes([TRANSPORT_VERSION]),
            scenario.report_nonce,
            len(scenario.envelope_wire).to_bytes(LENGTH_FIELD_BYTES, "big"),
            len(scenario.bundle_wire).to_bytes(LENGTH_FIELD_BYTES, "big"),
            len(scenario.approval_wire).to_bytes(LENGTH_FIELD_BYTES, "big"),
            scenario.envelope_wire,
            scenario.bundle_wire,
            scenario.approval_wire,
        )
    )


def _make_ingress(
    scenario: _Scenario,
    *,
    verifier_body: str = _VERIFIER_OK_BODY,
) -> tuple[ThreatHintV2Ingress, _RecordingSessionResolver]:
    """Wire the real governed promotion service behind the real ingress."""
    service = _governed_service(scenario, verifier_body=verifier_body)
    resolver = _RecordingSessionResolver(scenario.report_nonce)
    ingress = ThreatHintV2Ingress(
        service,
        resolver,
        scenario.vector["network_id"],
        lambda: scenario.current_time,
    )
    return ingress, resolver


def _make_worker(
    scenario: _Scenario,
    *,
    analyzer: Optional[ObservableAnalysisAnalyzer] = None,
    lease_seconds: int = 60,
) -> ObservableAnalysisWorker:
    return ObservableAnalysisWorker(
        _claim_service(scenario).outbox(),
        (DeterministicSemanticDraftAnalyzer() if analyzer is None else analyzer),
        lease_seconds=lease_seconds,
        analyzer_timeout_seconds=min(30.0, float(lease_seconds)),
    )


def _statement_digest(statement_wire: bytes) -> bytes:
    digest = hashlib.sha256()
    digest.update(STATEMENT_DIGEST_DOMAIN)
    digest.update(len(statement_wire).to_bytes(4, byteorder="big", signed=False))
    digest.update(statement_wire)
    return digest.digest()


def _kind_counts(bundle: ObservableBundle) -> Dict[str, int]:
    counts = {"file_sha256": 0, "api_import": 0, "byte_pattern": 0}
    for observable in bundle.observables:
        counts[observable.kind.value] += 1
    return counts


def _expected_candidate_binding(scenario: _Scenario) -> bytes:
    """Independently recompute the nonce-bound semantic-draft candidate binding."""
    bundle = ObservableBundle.parse_canonical(scenario.bundle_wire)
    draft = derive_semantic_draft(bundle)
    digest = hashlib.sha256()
    digest.update(SEMANTIC_DRAFT_BINDING_DOMAIN)
    digest.update(scenario.report_nonce)
    digest.update(draft.candidate_rule_sha256)
    return digest.digest()


def _assert_single_promotion_state(scenario: _Scenario) -> None:
    """Require exactly one governed acceptance and one pending outbox record."""
    ledger = _ledger_path(scenario)
    vector = scenario.vector
    expected_digest = _statement_digest(scenario.statement_wire)
    assert _schema_version(ledger) == 5
    assert _consumption_count(ledger) == 1
    assert _high_water(ledger) == scenario.current_time
    authority = _authority_state(ledger)
    assert authority is not None
    assert authority[0] == 1
    assert _pairing_rows(ledger) == [
        (
            expected_digest,
            bytes.fromhex(vector["approval_id_hex"]),
            bytes.fromhex(vector["observable_commitment_hex"]),
            vector["network_id"],
            scenario.current_time,
        )
    ]
    rows = _outbox_rows(ledger)
    assert len(rows) == 1
    (
        approval_id,
        commitment,
        bundle_wire,
        enqueued_at,
        deadline,
        lease_token,
        lease_expires_at,
    ) = rows[0]
    assert approval_id.hex() == vector["approval_id_hex"]
    assert commitment.hex() == vector["observable_commitment_hex"]
    assert bundle_wire == scenario.bundle_wire
    assert enqueued_at == scenario.current_time
    assert deadline == scenario.current_time + 86400
    assert lease_token is None
    assert lease_expires_at is None
    assert _outbox_binding_rows(ledger) == [
        (scenario.statement_wire, expected_digest, scenario.report_nonce)
    ]
    assert _result_rows(ledger) == []


@pytest.mark.asyncio
async def test_transport_to_durable_semantic_draft_result_binds_every_identity(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    ingress, resolver = _make_ingress(scenario)
    wire = _transport_wire(scenario)
    ledger = _ledger_path(scenario)
    vector = scenario.vector

    ack = ingress.process(wire)

    assert ack.status == "accepted"
    assert ack.payload_digest == hashlib.sha256(wire).hexdigest()
    assert resolver.lookups == [scenario.report_nonce]
    _assert_single_promotion_state(scenario)

    # Pending work cannot be deleted without a durable result.
    outbox = _claim_service(scenario).outbox()
    claim = outbox.claim(current_time=scenario.current_time, lease_seconds=60)
    assert claim is not None
    assert claim.statement_digest == _statement_digest(scenario.statement_wire)
    assert claim.approval_id.hex() == vector["approval_id_hex"]
    assert claim.observable_commitment.hex() == vector["observable_commitment_hex"]
    assert claim.report_nonce == scenario.report_nonce
    assert claim.statement_wire == scenario.statement_wire
    assert claim.bundle_wire == scenario.bundle_wire
    with pytest.raises(ObservableApprovalOutboxError):
        outbox.acknowledge(approval_id=claim.approval_id, lease_token=claim.lease_token)
    assert len(_outbox_rows(ledger)) == 1
    assert _result_rows(ledger) == []

    # The leased claim blocks a second claim until it completes or expires.
    blocking_worker = _make_worker(scenario)
    assert (
        await blocking_worker.process_next(current_time=scenario.current_time) is None
    )

    # Complete exactly once through the restarted worker after lease expiry.
    completion = await blocking_worker.process_next(current_time=claim.lease_expires_at)
    assert completion is not None
    assert completion.approval_id == claim.approval_id
    assert completion.input_identity != claim.input_identity
    assert completion.completed_at == claim.lease_expires_at
    assert completion.retention_deadline == scenario.current_time + 86400

    # Work is deleted only together with the durable result.
    assert _outbox_rows(ledger) == []
    rows = _result_rows(ledger)
    assert len(rows) == 1
    assert rows[0][0] == claim.approval_id
    assert rows[0][2] == completion.result_digest

    stored = outbox.result(
        approval_id=claim.approval_id,
        current_time=claim.lease_expires_at,
    )
    assert stored is not None
    assert stored.result_digest == completion.result_digest
    assert stored.input_identity == completion.input_identity
    assert stored.completed_at == completion.completed_at
    assert stored.retention_deadline == completion.retention_deadline

    bundle = ObservableBundle.parse_canonical(scenario.bundle_wire)
    kind_counts = _kind_counts(bundle)
    assert json.loads(stored.result_wire.decode("ascii")) == {
        "schema_version": SEMANTIC_DRAFT_RESULT_SCHEMA_VERSION,
        "result_kind": SEMANTIC_DRAFT_RESULT_KIND,
        "analyzer_id": SEMANTIC_DRAFT_ANALYZER_ID,
        "approval_id": vector["approval_id_hex"],
        "input_identity": completion.input_identity.hex(),
        "statement_digest": _statement_digest(scenario.statement_wire).hex(),
        "observable_commitment": vector["observable_commitment_hex"],
        "observable_count": len(bundle.observables),
        "observable_kind_counts": kind_counts,
        "candidate_binding_sha256": _expected_candidate_binding(scenario).hex(),
        "rule_compile_ok": True,
    }
    assert sum(kind_counts.values()) == len(bundle.observables)
    # The exact field set above grants no actionable authority, and no
    # candidate rule source fragment is ever persisted.
    result_text = stored.result_wire.decode("ascii")
    for forbidden in (
        "confidence_bps",
        "should_submit",
        "strings:",
        "condition:",
        "prometheus_observable_semantic_draft_v1",
    ):
        assert forbidden not in result_text

    assert (
        await blocking_worker.process_next(current_time=claim.lease_expires_at) is None
    )
    assert len(_result_rows(ledger)) == 1


def test_malformed_and_oversized_transport_fail_before_any_trusted_state(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    marker = scenario.directory / "verifier-ran"
    body = f"printf 'ran\\n' >> {shlex.quote(str(marker))}\n" + _VERIFIER_OK_BODY
    ingress, resolver = _make_ingress(scenario, verifier_body=body)
    wire = _transport_wire(scenario)
    ledger = _ledger_path(scenario)

    unbound = (b"", b"P" * (MAX_TRANSPORT_PAYLOAD_BYTES + 1))
    for bad_wire in unbound:
        ack = ingress.process(bad_wire)
        assert ack.status == "rejected"
        assert ack.payload_digest == _ZERO_DIGEST

    bound = (
        wire[:-1],
        wire + b"\x00",
        b"XHT2" + wire[4:],
        wire[:10] + bytes([wire[10] ^ 0x01]) + wire[11:],
    )
    for bad_wire in bound:
        ack = ingress.process(bad_wire)
        assert ack.status == "rejected"
        assert ack.payload_digest == hashlib.sha256(bad_wire).hexdigest()

    # Nothing reached the trusted resolver, the promotion service, or the ledger.
    assert resolver.lookups == []
    assert not marker.exists()
    assert _consumption_count(ledger) == 0
    assert _high_water(ledger) == 0
    assert _authority_state(ledger) is None
    assert _outbox_rows(ledger) == []
    assert _result_rows(ledger) == []

    # The rejections leave the trusted path fully usable.
    ack = ingress.process(wire)
    assert ack.status == "accepted"
    _assert_single_promotion_state(scenario)


@pytest.mark.asyncio
async def test_replay_and_restart_submissions_share_one_durable_result_path(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    ingress, _resolver = _make_ingress(scenario)
    wire = _transport_wire(scenario)
    ledger = _ledger_path(scenario)

    first = ingress.process(wire)
    assert first.status == "accepted"

    duplicate = ingress.process(wire)
    assert duplicate.status == "rejected"
    assert duplicate.payload_digest == first.payload_digest

    # A full restart on the same owner policies keeps replay durable.
    restarted_ingress, _restarted_resolver = _make_ingress(scenario)
    replayed = restarted_ingress.process(wire)
    assert replayed.status == "rejected"
    assert replayed.payload_digest == first.payload_digest

    assert _consumption_count(ledger) == 1
    assert len(_outbox_rows(ledger)) == 1
    assert len(_pairing_rows(ledger)) == 1

    worker = _make_worker(scenario)
    completion = await worker.process_next(current_time=scenario.current_time)
    assert completion is not None
    assert _outbox_rows(ledger) == []
    assert len(_result_rows(ledger)) == 1
    assert await worker.process_next(current_time=scenario.current_time) is None
    assert len(_result_rows(ledger)) == 1


@pytest.mark.asyncio
async def test_concurrent_duplicate_submissions_have_exactly_one_durable_winner(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    ingress, _resolver = _make_ingress(scenario)
    wire = _transport_wire(scenario)
    ledger = _ledger_path(scenario)
    barrier = threading.Barrier(2)
    outcomes: List[str] = []

    def attempt() -> None:
        barrier.wait(timeout=5)
        deadline = time.monotonic() + 15
        while True:
            ack = ingress.process(wire)
            if ack.status != "busy":
                outcomes.append(ack.status)
                return
            if time.monotonic() > deadline:
                raise AssertionError("duplicate submission stayed busy")
            time.sleep(0.02)

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert all(not thread.is_alive() for thread in threads)
    assert sorted(outcomes) == ["accepted", "rejected"]
    assert _consumption_count(ledger) == 1
    assert len(_outbox_rows(ledger)) == 1
    assert len(_pairing_rows(ledger)) == 1

    worker = _make_worker(scenario)
    completion = await worker.process_next(current_time=scenario.current_time)
    assert completion is not None
    assert _outbox_rows(ledger) == []
    assert len(_result_rows(ledger)) == 1
    assert await worker.process_next(current_time=scenario.current_time) is None
    assert len(_result_rows(ledger)) == 1


@pytest.mark.asyncio
async def test_lease_expiry_and_restart_recover_without_duplicate_result(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    ingress, _resolver = _make_ingress(scenario)
    assert ingress.process(_transport_wire(scenario)).status == "accepted"
    ledger = _ledger_path(scenario)

    outbox = _claim_service(scenario).outbox()
    claim = outbox.claim(current_time=scenario.current_time, lease_seconds=10)
    assert claim is not None

    # Restarted worker mid-lease: the record stays leased and unprocessed.
    worker = _make_worker(scenario)
    assert await worker.process_next(current_time=scenario.current_time + 5) is None
    assert len(_outbox_rows(ledger)) == 1
    assert _result_rows(ledger) == []

    # After lease expiry the restarted worker recovers the work exactly once.
    completion = await worker.process_next(current_time=claim.lease_expires_at)
    assert completion is not None
    assert completion.approval_id == claim.approval_id
    assert _outbox_rows(ledger) == []
    assert len(_result_rows(ledger)) == 1
    assert await worker.process_next(current_time=claim.lease_expires_at) is None
    assert len(_result_rows(ledger)) == 1


@pytest.mark.asyncio
async def test_injected_analysis_failure_preserves_recoverable_work(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    ingress, _resolver = _make_ingress(scenario)
    assert ingress.process(_transport_wire(scenario)).status == "accepted"
    ledger = _ledger_path(scenario)

    failing_worker = _make_worker(
        scenario, analyzer=_FailingAnalyzer(), lease_seconds=10
    )
    with pytest.raises(
        ObservableAnalysisWorkerError,
        match=r"^observable analysis worker failure$",
    ) as exc_info:
        await failing_worker.process_next(current_time=scenario.current_time)
    assert _ANALYSIS_FAILURE_MARKER not in str(exc_info.value)

    # The failure leaves the work recoverable and the approval state consistent.
    assert len(_outbox_rows(ledger)) == 1
    assert _result_rows(ledger) == []
    assert _consumption_count(ledger) == 1
    assert len(_pairing_rows(ledger)) == 1

    recovered = _make_worker(scenario)
    completion = await recovered.process_next(current_time=scenario.current_time + 10)
    assert completion is not None
    assert _outbox_rows(ledger) == []
    assert len(_result_rows(ledger)) == 1


@pytest.mark.asyncio
async def test_injected_completion_failure_rolls_back_and_recovers(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    ingress, _resolver = _make_ingress(scenario)
    assert ingress.process(_transport_wire(scenario)).status == "accepted"
    ledger = _ledger_path(scenario)
    with sqlite3.connect(ledger) as connection:
        connection.execute("""
            CREATE TRIGGER reject_result_insert
            BEFORE INSERT ON observable_analysis_results
            BEGIN
                SELECT RAISE(ABORT, 'synthetic-completion-failure-marker');
            END
            """)

    failing_worker = _make_worker(scenario, lease_seconds=10)
    with pytest.raises(ObservableApprovalOutboxError) as exc_info:
        await failing_worker.process_next(current_time=scenario.current_time)
    assert _COMPLETION_FAILURE_MARKER not in str(exc_info.value)

    # No partial result and no approval/pairing inconsistency after rollback.
    assert len(_outbox_rows(ledger)) == 1
    assert _result_rows(ledger) == []
    assert _consumption_count(ledger) == 1
    assert len(_pairing_rows(ledger)) == 1

    with sqlite3.connect(ledger) as connection:
        connection.execute("DROP TRIGGER reject_result_insert")
    recovered = _make_worker(scenario)
    completion = await recovered.process_next(current_time=scenario.current_time + 10)
    assert completion is not None
    assert _outbox_rows(ledger) == []
    assert len(_result_rows(ledger)) == 1


def test_pipeline_modules_have_no_gh177_semantic_quality_wiring() -> None:
    for module in (
        worker_module,
        consumption_module,
        draft_module,
        acceptance_module,
        governance_module,
        ingress_module,
        preflight_module,
        promotion_module,
        transport_module,
        verified_preflight_module,
    ):
        module_path = module.__file__
        assert module_path is not None
        source = Path(module_path).read_text(encoding="utf-8")
        assert "yara_semantic_quality" not in source
