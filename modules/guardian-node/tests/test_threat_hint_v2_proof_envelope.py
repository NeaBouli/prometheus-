"""Parity and security tests for the local canonical ThreatHint v2 proof envelope."""

# Pytest test names provide the scenario descriptions.
# pylint: disable=missing-function-docstring

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable

import pytest

from jaeger.threat_hint_ingress import CanonicalThreatHint, ThreatHintIngressError
from jaeger.threat_hint_v2_proof_envelope import (
    MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES,
    PROTOCOL_ID,
    RELATION_ID,
    ThreatHintV2ProofEnvelope,
    ThreatHintV2ProofEnvelopeError,
)

VECTOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "threat-hint"
    / "tests"
    / "vectors"
    / "threat-hint-v2-proof-envelope-v1.json"
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
        "protocol_id",
        "relation_id",
        "valid_cases",
        "invalid_cases",
    ]
    assert parsed["vector_schema_version"] == 1
    assert parsed["protocol_id"] == PROTOCOL_ID
    assert parsed["relation_id"] == RELATION_ID
    return parsed


def _wire(case: dict) -> bytes:
    assert set(case.keys()) in ({"name", "trusted_network_id", "wire_hex"},)
    return bytes.fromhex(case["wire_hex"])


def _base_case() -> dict:
    return {case["name"]: case for case in _corpus()["valid_cases"]}[
        "base_review_required"
    ]


def test_shared_valid_vectors_parse_with_exact_bytes_and_binding() -> None:
    corpus = _corpus()
    assert len(corpus["valid_cases"]) == 3
    names = set()

    for case in corpus["valid_cases"]:
        assert case["name"] not in names
        names.add(case["name"])
        wire = _wire(case)
        assert len(wire) <= MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES

        envelope = ThreatHintV2ProofEnvelope.parse_canonical(
            wire, case["trusted_network_id"]
        )
        assert envelope.canonical_bytes == wire
        assert envelope.schema_version == 2
        assert envelope.protocol_id == PROTOCOL_ID
        assert envelope.relation_id == RELATION_ID
        assert envelope.parsed_statement.network_id == case["trusted_network_id"]
        assert (
            envelope.statement_digest
            == envelope.parsed_statement.statement_digest().hex()
        )
        proof = envelope.proof_bytes()
        assert proof.hex() == envelope.proof
        assert 1 <= len(proof) <= 1024


def test_proof_size_boundaries_are_enforced() -> None:
    cases = {case["name"]: case for case in _corpus()["valid_cases"]}
    min_case = cases["public_auto_min_proof"]
    max_case = cases["mainnet_max_proof"]

    minimum = ThreatHintV2ProofEnvelope.parse_canonical(
        _wire(min_case), min_case["trusted_network_id"]
    )
    assert minimum.proof_bytes() == b"\x00"

    maximum = ThreatHintV2ProofEnvelope.parse_canonical(
        _wire(max_case), max_case["trusted_network_id"]
    )
    assert len(maximum.proof_bytes()) == 1024


def test_shared_invalid_vectors_fail_closed_with_one_error() -> None:
    cases = _corpus()["invalid_cases"]
    assert len(cases) == 30
    names = set()

    for case in cases:
        assert case["name"] not in names
        names.add(case["name"])
        with pytest.raises(
            ThreatHintV2ProofEnvelopeError,
            match=r"^invalid threat-hint v2 proof envelope$",
        ):
            ThreatHintV2ProofEnvelope.parse_canonical(
                _wire(case), case["trusted_network_id"]
            )


def test_cross_version_envelopes_are_rejected_bidirectionally() -> None:
    case = _base_case()
    v2_wire = _wire(case)

    v1_hint = CanonicalThreatHint(
        schema_version=1,
        threat_hash="01" * 32,
        confidence_bps=420,
        indicator_type="file_hash",
        proof_system="groth16_kip16_v1",
        proof="aa" * 16,
        report_nonce="ab" * 32,
        observed_at=1_700_000_000,
    )
    v1_wire = v1_hint.to_wire()

    with pytest.raises(ThreatHintV2ProofEnvelopeError):
        ThreatHintV2ProofEnvelope.parse_canonical(v1_wire, "testnet-10")
    with pytest.raises(ThreatHintIngressError):
        CanonicalThreatHint.from_wire(v2_wire)


def test_envelope_size_limit_is_fail_closed() -> None:
    with pytest.raises(ThreatHintV2ProofEnvelopeError):
        ThreatHintV2ProofEnvelope.parse_canonical(
            b"{" * (MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES + 1), "testnet-10"
        )
    case = _base_case()
    assert len(_wire(case)) < MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES


def test_direct_subclass_and_nonbytes_construction_are_rejected() -> None:
    case = _base_case()
    wire = _wire(case)

    with pytest.raises(TypeError):
        ThreatHintV2ProofEnvelope()
    with pytest.raises(ThreatHintV2ProofEnvelopeError):
        ThreatHintV2ProofEnvelope.parse_canonical(
            bytearray(wire), case["trusted_network_id"]  # type: ignore[arg-type]
        )
    with pytest.raises(ThreatHintV2ProofEnvelopeError):
        ThreatHintV2ProofEnvelope.parse_canonical(wire, 10)  # type: ignore[arg-type]

    class ForgedEnvelope(ThreatHintV2ProofEnvelope):
        """Adversarial parser subclass used to test exact-type enforcement."""

    with pytest.raises(ThreatHintV2ProofEnvelopeError):
        ForgedEnvelope.parse_canonical(wire, case["trusted_network_id"])


def test_valid_shape_mutation_cannot_serialize_or_decode() -> None:
    case = _base_case()
    envelope = ThreatHintV2ProofEnvelope.parse_canonical(
        _wire(case), case["trusted_network_id"]
    )
    object.__setattr__(envelope, "proof", "bb" * 16)

    with pytest.raises(ThreatHintV2ProofEnvelopeError):
        _ = envelope.canonical_bytes

    object.__setattr__(envelope, "proof", "aa" * 16)
    object.__setattr__(envelope, "statement_digest", "ff" * 32)
    with pytest.raises(ThreatHintV2ProofEnvelopeError):
        _ = envelope.canonical_bytes
    with pytest.raises(ThreatHintV2ProofEnvelopeError):
        envelope.proof_bytes()


def test_manually_forged_valid_shape_instance_cannot_serialize_or_decode() -> None:
    case = _base_case()
    parsed = ThreatHintV2ProofEnvelope.parse_canonical(
        _wire(case), case["trusted_network_id"]
    )
    forged = object.__new__(ThreatHintV2ProofEnvelope)
    for field_name in (
        "schema_version",
        "protocol_id",
        "relation_id",
        "statement",
        "statement_digest",
        "proof",
        "parsed_statement",
    ):
        object.__setattr__(forged, field_name, getattr(parsed, field_name))

    with pytest.raises(ThreatHintV2ProofEnvelopeError):
        _ = forged.canonical_bytes
    with pytest.raises(ThreatHintV2ProofEnvelopeError):
        forged.proof_bytes()
