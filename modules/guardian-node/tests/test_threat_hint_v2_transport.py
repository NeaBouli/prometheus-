"""Parity and security tests for the local ThreatHint v2 transport payload."""

# Pytest test names provide the scenario descriptions.
# pylint: disable=missing-function-docstring

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable

import pytest

from jaeger.threat_hint_v2_transport import (
    MAX_TRANSPORT_APPROVAL_BYTES,
    MAX_TRANSPORT_BUNDLE_BYTES,
    MAX_TRANSPORT_ENVELOPE_BYTES,
    MAX_TRANSPORT_PAYLOAD_BYTES,
    REPORT_NONCE_BYTES,
    TRANSPORT_MAGIC,
    TRANSPORT_VERSION,
    ThreatHintV2TransportError,
    ThreatHintV2TransportPayload,
)

VECTOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "threat-hint"
    / "tests"
    / "vectors"
    / "threat-hint-v2-transport-v1.json"
)


def _reject_duplicate_keys(items: Iterable[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate vector key")
        result[key] = value
    return result


def _corpus() -> dict:
    parsed = json.loads(
        VECTOR_PATH.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
    )
    assert list(parsed.keys()) == [
        "vector_schema_version",
        "magic_hex",
        "version",
        "max_envelope_bytes",
        "max_bundle_bytes",
        "max_approval_bytes",
        "max_payload_bytes",
        "valid_cases",
        "invalid_cases",
    ]
    assert parsed["vector_schema_version"] == 1
    assert bytes.fromhex(parsed["magic_hex"]) == TRANSPORT_MAGIC
    assert parsed["version"] == TRANSPORT_VERSION
    assert parsed["max_envelope_bytes"] == MAX_TRANSPORT_ENVELOPE_BYTES
    assert parsed["max_bundle_bytes"] == MAX_TRANSPORT_BUNDLE_BYTES
    assert parsed["max_approval_bytes"] == MAX_TRANSPORT_APPROVAL_BYTES
    assert parsed["max_payload_bytes"] == MAX_TRANSPORT_PAYLOAD_BYTES
    return parsed


def _wire(case: dict) -> bytes:
    assert set(case.keys()) == {"name", "trusted_network_id", "wire_hex"}
    return bytes.fromhex(case["wire_hex"])


def _base_case() -> dict:
    return {case["name"]: case for case in _corpus()["valid_cases"]}[
        "base_review_required"
    ]


def test_shared_valid_vectors_parse_with_exact_bytes_and_nonce_binding() -> None:
    corpus = _corpus()
    assert len(corpus["valid_cases"]) == 2
    names = set()

    for case in corpus["valid_cases"]:
        assert case["name"] not in names
        names.add(case["name"])
        wire = _wire(case)
        assert len(wire) <= MAX_TRANSPORT_PAYLOAD_BYTES

        payload = ThreatHintV2TransportPayload.parse_canonical(
            wire, case["trusted_network_id"]
        )
        assert payload.canonical_bytes == wire

        # The nonce is only an untrusted session lookup key; it must equal the
        # envelope statement nonce but grants no authority by itself.
        assert isinstance(payload.report_nonce, bytes)
        assert len(payload.report_nonce) == REPORT_NONCE_BYTES
        assert (
            payload.parsed_envelope.parsed_statement.report_nonce
            == payload.report_nonce.hex()
        )
        assert (
            payload.parsed_envelope.parsed_statement.network_id
            == case["trusted_network_id"]
        )

        assert payload.envelope_wire == payload.parsed_envelope.canonical_bytes
        assert payload.bundle_wire == payload.parsed_bundle.canonical_bytes
        assert 1 <= len(payload.envelope_wire) <= MAX_TRANSPORT_ENVELOPE_BYTES
        assert 1 <= len(payload.bundle_wire) <= MAX_TRANSPORT_BUNDLE_BYTES
        assert 1 <= len(payload.approval_wire) <= MAX_TRANSPORT_APPROVAL_BYTES


def test_shared_invalid_vectors_fail_closed_with_one_error() -> None:
    cases = _corpus()["invalid_cases"]
    assert len(cases) == 19
    names = set()

    for case in cases:
        assert case["name"] not in names
        names.add(case["name"])
        with pytest.raises(
            ThreatHintV2TransportError,
            match=r"^invalid threat-hint v2 transport payload$",
        ):
            ThreatHintV2TransportPayload.parse_canonical(
                _wire(case), case["trusted_network_id"]
            )


def test_payload_size_limit_is_fail_closed() -> None:
    with pytest.raises(ThreatHintV2TransportError):
        ThreatHintV2TransportPayload.parse_canonical(
            b"P" * (MAX_TRANSPORT_PAYLOAD_BYTES + 1), "testnet-10"
        )
    assert len(_wire(_base_case())) < MAX_TRANSPORT_PAYLOAD_BYTES


def test_direct_subclass_and_nonbytes_construction_are_rejected() -> None:
    case = _base_case()
    wire = _wire(case)

    with pytest.raises(TypeError):
        ThreatHintV2TransportPayload()
    with pytest.raises(ThreatHintV2TransportError):
        ThreatHintV2TransportPayload.parse_canonical(
            bytearray(wire), case["trusted_network_id"]  # type: ignore[arg-type]
        )
    with pytest.raises(ThreatHintV2TransportError):
        ThreatHintV2TransportPayload.parse_canonical(wire, 10)  # type: ignore[arg-type]

    class ForgedPayload(ThreatHintV2TransportPayload):
        """Adversarial parser subclass used to test exact-type enforcement."""

    with pytest.raises(ThreatHintV2TransportError):
        ForgedPayload.parse_canonical(wire, case["trusted_network_id"])


def test_valid_shape_mutation_cannot_serialize() -> None:
    case = _base_case()
    payload = ThreatHintV2TransportPayload.parse_canonical(
        _wire(case), case["trusted_network_id"]
    )
    object.__setattr__(payload, "report_nonce", b"\x00" * REPORT_NONCE_BYTES)

    with pytest.raises(ThreatHintV2TransportError):
        _ = payload.canonical_bytes


def test_manually_forged_valid_shape_instance_cannot_serialize() -> None:
    case = _base_case()
    parsed = ThreatHintV2TransportPayload.parse_canonical(
        _wire(case), case["trusted_network_id"]
    )
    forged = object.__new__(ThreatHintV2TransportPayload)
    for field_name in (
        "report_nonce",
        "envelope_wire",
        "bundle_wire",
        "approval_wire",
        "parsed_envelope",
        "parsed_bundle",
    ):
        object.__setattr__(forged, field_name, getattr(parsed, field_name))

    with pytest.raises(ThreatHintV2TransportError):
        _ = forged.canonical_bytes


def test_approval_wire_is_shape_checked_only_and_stays_downstream() -> None:
    # A shape-valid approval with a nonsense signature still parses at this
    # layer: full verification needs a separately trusted context downstream.
    case = _base_case()
    payload = ThreatHintV2TransportPayload.parse_canonical(
        _wire(case), case["trusted_network_id"]
    )
    assert payload.approval_wire.startswith(b'{"schema_version":1,')

    case2 = {case["name"]: case for case in _corpus()["valid_cases"]}[
        "public_auto_min_proof"
    ]
    payload2 = ThreatHintV2TransportPayload.parse_canonical(
        _wire(case2), case2["trusted_network_id"]
    )
    assert b'"signature":"' + b"99" * 64 + b'"' in payload2.approval_wire
