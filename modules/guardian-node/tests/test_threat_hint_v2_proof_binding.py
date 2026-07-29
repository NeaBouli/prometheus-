"""Parity and security tests for the local ThreatHint-v2 proof binding."""

# Pytest test names provide the scenario descriptions.
# pylint: disable=missing-function-docstring

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable

import pytest

from jaeger.relation_manifest_v2 import (
    PROTOCOL_ID,
    PUBLIC_INPUT_ENCODING,
    RELATION_ID,
    STATEMENT_DIGEST_DOMAIN_HEX,
)
from jaeger.threat_hint_v2_proof_binding import (
    ThreatHintV2ProofBinding,
    ThreatHintV2ProofBindingError,
)

VECTOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "threat-proof"
    / "tests"
    / "vectors"
    / "threat-hint-v2-proof-binding-v1.json"
)

VALID_VECTOR_COUNT = 5
INVALID_VECTOR_COUNT = 28
VALID_CASE_KEYS = {
    "name",
    "trusted_network_id",
    "envelope_wire_hex",
    "manifest_wire_hex",
    "manifest_sha256_hex",
    "statement_digest_hex",
    "public_input_first_half_hex",
    "public_input_second_half_hex",
}
INVALID_CASE_KEYS = {
    "name",
    "trusted_network_id",
    "trusted_manifest_sha256_hex",
    "envelope_wire_hex",
    "manifest_wire_hex",
}


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
        "statement_digest_domain_hex",
        "public_input_encoding",
        "valid_cases",
        "invalid_cases",
    ]
    assert parsed["vector_schema_version"] == 1
    assert parsed["protocol_id"] == PROTOCOL_ID
    assert parsed["relation_id"] == RELATION_ID
    assert parsed["statement_digest_domain_hex"] == STATEMENT_DIGEST_DOMAIN_HEX
    assert parsed["public_input_encoding"] == PUBLIC_INPUT_ENCODING
    return parsed


def _valid_case(name: str) -> dict:
    cases = {case["name"]: case for case in _corpus()["valid_cases"]}
    return cases[name]


def _bind_valid(case: dict) -> ThreatHintV2ProofBinding:
    assert set(case.keys()) == VALID_CASE_KEYS
    return ThreatHintV2ProofBinding.bind_canonical(
        bytes.fromhex(case["envelope_wire_hex"]),
        bytes.fromhex(case["manifest_wire_hex"]),
        case["trusted_network_id"],
        case["manifest_sha256_hex"],
    )


def _bind_invalid(case: dict) -> None:
    assert set(case.keys()) == INVALID_CASE_KEYS
    with pytest.raises(
        ThreatHintV2ProofBindingError,
        match=r"^invalid threat-hint v2 proof binding$",
    ):
        ThreatHintV2ProofBinding.bind_canonical(
            bytes.fromhex(case["envelope_wire_hex"]),
            bytes.fromhex(case["manifest_wire_hex"]),
            case["trusted_network_id"],
            case["trusted_manifest_sha256_hex"],
        )


def test_shared_corpus_has_exact_schema_and_unique_names() -> None:
    corpus = _corpus()
    assert len(corpus["valid_cases"]) == VALID_VECTOR_COUNT
    assert len(corpus["invalid_cases"]) == INVALID_VECTOR_COUNT
    names = set()
    for case in corpus["valid_cases"] + corpus["invalid_cases"]:
        assert case["name"] not in names
        names.add(case["name"])
    assert len(names) == VALID_VECTOR_COUNT + INVALID_VECTOR_COUNT


def test_shared_valid_vectors_bind_with_exact_anchors_and_claimed_inputs() -> None:
    corpus = _corpus()
    manifest_digests = set()
    statement_digests = set()

    for case in corpus["valid_cases"]:
        binding = _bind_valid(case)
        manifest_wire = bytes.fromhex(case["manifest_wire_hex"])
        assert hashlib.sha256(manifest_wire).hexdigest() == case["manifest_sha256_hex"]

        assert binding.raw_manifest_sha256_hex == case["manifest_sha256_hex"]
        assert binding.statement_digest_hex == case["statement_digest_hex"]
        assert binding.envelope.statement_digest == case["statement_digest_hex"]
        assert binding.public_input_first_half == bytes.fromhex(
            case["public_input_first_half_hex"]
        )
        assert binding.public_input_second_half == bytes.fromhex(
            case["public_input_second_half_hex"]
        )
        assert len(binding.public_input_first_half) == 16
        assert len(binding.public_input_second_half) == 16
        assert case["statement_digest_hex"] == (
            case["public_input_first_half_hex"] + case["public_input_second_half_hex"]
        )

        assert binding.manifest.network_id == case["trusted_network_id"]
        assert (
            binding.envelope.parsed_statement.network_id == case["trusted_network_id"]
        )
        assert binding.envelope.protocol_id == binding.manifest.protocol_id
        assert binding.envelope.relation_id == binding.manifest.relation_id
        assert binding.envelope.canonical_bytes == bytes.fromhex(
            case["envelope_wire_hex"]
        )
        assert binding.manifest.canonical_bytes == manifest_wire

        manifest_digests.add(case["manifest_sha256_hex"])
        statement_digests.add(case["statement_digest_hex"])

    assert len(manifest_digests) == VALID_VECTOR_COUNT
    assert len(statement_digests) == VALID_VECTOR_COUNT


def test_shared_invalid_vectors_fail_closed_with_one_redacted_error() -> None:
    corpus = _corpus()
    for case in corpus["invalid_cases"]:
        _bind_invalid(case)


def test_trusted_network_binding_is_enforced_for_every_valid_vector() -> None:
    corpus = _corpus()
    for case in corpus["valid_cases"]:
        envelope_wire = bytes.fromhex(case["envelope_wire_hex"])
        manifest_wire = bytes.fromhex(case["manifest_wire_hex"])
        for other in corpus["valid_cases"]:
            if other["trusted_network_id"] != case["trusted_network_id"]:
                with pytest.raises(ThreatHintV2ProofBindingError):
                    ThreatHintV2ProofBinding.bind_canonical(
                        envelope_wire,
                        manifest_wire,
                        other["trusted_network_id"],
                        case["manifest_sha256_hex"],
                    )


def test_v1_wires_reject_the_binding_but_retain_their_own_shape() -> None:
    corpus = _corpus()
    cases = {case["name"]: case for case in corpus["invalid_cases"]}

    envelope_case = cases["v1_envelope_confusion"]
    v1_envelope_wire = bytes.fromhex(envelope_case["envelope_wire_hex"])
    assert json.loads(v1_envelope_wire.decode("utf-8"))["schema_version"] == 1
    _bind_invalid(envelope_case)

    manifest_case = cases["v1_manifest_confusion"]
    v1_manifest_wire = bytes.fromhex(manifest_case["manifest_wire_hex"])
    assert json.loads(v1_manifest_wire.decode("utf-8"))["schema_version"] == 1
    _bind_invalid(manifest_case)


def test_derived_claimed_inputs_are_not_proof_acceptance() -> None:
    case = _valid_case("base_testnet")
    binding = _bind_valid(case)

    digest = bytes.fromhex(binding.statement_digest_hex)
    assert binding.public_input_first_half == digest[:16]
    assert binding.public_input_second_half == digest[16:]
    # The proof bytes remain opaque claimed data; nothing is verified here.
    assert binding.envelope.proof_bytes().hex() == "aa" * 16


def test_direct_subclass_and_typed_argument_construction_are_rejected() -> None:
    case = _valid_case("base_testnet")
    envelope_wire = bytes.fromhex(case["envelope_wire_hex"])
    manifest_wire = bytes.fromhex(case["manifest_wire_hex"])
    anchor = case["manifest_sha256_hex"]

    with pytest.raises(TypeError):
        ThreatHintV2ProofBinding()
    with pytest.raises(ThreatHintV2ProofBindingError):
        ThreatHintV2ProofBinding.bind_canonical(
            bytearray(envelope_wire), manifest_wire, "testnet-10", anchor  # type: ignore[arg-type]
        )
    with pytest.raises(ThreatHintV2ProofBindingError):
        ThreatHintV2ProofBinding.bind_canonical(
            envelope_wire, manifest_wire, 10, anchor  # type: ignore[arg-type]
        )
    with pytest.raises(ThreatHintV2ProofBindingError):
        ThreatHintV2ProofBinding.bind_canonical(
            envelope_wire, manifest_wire, "testnet-10", anchor.encode("utf-8")  # type: ignore[arg-type]
        )

    class ForgedBinding(ThreatHintV2ProofBinding):
        """Adversarial binding subclass used to test exact-type enforcement."""

    with pytest.raises(ThreatHintV2ProofBindingError):
        ForgedBinding.bind_canonical(envelope_wire, manifest_wire, "testnet-10", anchor)


def test_valid_shape_mutation_cannot_read_derived_values() -> None:
    case = _valid_case("base_testnet")
    binding = _bind_valid(case)
    other = _bind_valid(_valid_case("alt_manifest_testnet"))

    object.__setattr__(binding, "manifest", other.manifest)
    with pytest.raises(ThreatHintV2ProofBindingError):
        _ = binding.raw_manifest_sha256_hex
    with pytest.raises(ThreatHintV2ProofBindingError):
        _ = binding.statement_digest_hex

    object.__setattr__(binding, "manifest", _bind_valid(case).manifest)
    object.__setattr__(binding, "envelope", other.envelope)
    with pytest.raises(ThreatHintV2ProofBindingError):
        _ = binding.public_input_first_half
    with pytest.raises(ThreatHintV2ProofBindingError):
        _ = binding.public_input_second_half


def test_same_statement_different_proof_substitution_fails_closed() -> None:
    case = _valid_case("base_testnet")
    envelope = json.loads(bytes.fromhex(case["envelope_wire_hex"]))
    envelope["proof"] = "bb" * 16
    alternate_wire = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    alternate = ThreatHintV2ProofBinding.bind_canonical(
        alternate_wire,
        bytes.fromhex(case["manifest_wire_hex"]),
        case["trusted_network_id"],
        case["manifest_sha256_hex"],
    )
    binding = _bind_valid(case)

    assert alternate.statement_digest_hex == binding.statement_digest_hex
    assert alternate.envelope.proof_bytes() != binding.envelope.proof_bytes()
    object.__setattr__(binding, "envelope", alternate.envelope)

    with pytest.raises(ThreatHintV2ProofBindingError):
        _ = binding.raw_manifest_sha256_hex
    with pytest.raises(ThreatHintV2ProofBindingError):
        _ = binding.public_input_first_half


def test_manually_forged_valid_shape_instance_cannot_read_derived_values() -> None:
    case = _valid_case("base_testnet")
    parsed = _bind_valid(case)
    forged = object.__new__(ThreatHintV2ProofBinding)
    object.__setattr__(forged, "envelope", parsed.envelope)
    object.__setattr__(forged, "manifest", parsed.manifest)

    with pytest.raises(ThreatHintV2ProofBindingError):
        _ = forged.raw_manifest_sha256_hex
    with pytest.raises(ThreatHintV2ProofBindingError):
        _ = forged.statement_digest_hex
    with pytest.raises(ThreatHintV2ProofBindingError):
        _ = forged.public_input_first_half
    with pytest.raises(ThreatHintV2ProofBindingError):
        _ = forged.public_input_second_half


def test_nested_parser_errors_stay_redacted_through_the_binding() -> None:
    case = _valid_case("base_testnet")
    envelope_wire = bytes.fromhex(case["envelope_wire_hex"])
    tampered = envelope_wire.replace(b"7500", b"7501")
    anchor = case["manifest_sha256_hex"]

    with pytest.raises(ThreatHintV2ProofBindingError) as captured:
        ThreatHintV2ProofBinding.bind_canonical(
            tampered,
            bytes.fromhex(case["manifest_wire_hex"]),
            "testnet-10",
            anchor,
        )
    assert str(captured.value) == "invalid threat-hint v2 proof binding"
    assert anchor not in str(captured.value)
    assert "7501" not in str(captured.value)
