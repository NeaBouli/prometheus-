"""Parity and security tests for the local canonical ThreatHint v2 statement."""

# Pytest test names provide the scenario descriptions.
# pylint: disable=missing-function-docstring

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable

import pytest

from jaeger.threat_hint_v2_statement import (
    MAX_CANONICAL_V2_STATEMENT_BYTES,
    STATEMENT_DIGEST_DOMAIN,
    ThreatHintV2DisclosureClass,
    ThreatHintV2Statement,
    ThreatHintV2StatementError,
)

VECTOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "threat-hint"
    / "tests"
    / "vectors"
    / "threat-hint-v2-statement-v1.json"
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
        "statement_digest_domain_hex",
        "valid_cases",
        "invalid_cases",
    ]
    assert parsed["vector_schema_version"] == 1
    assert parsed["statement_digest_domain_hex"] == STATEMENT_DIGEST_DOMAIN.hex()
    return parsed


def _wire(case: dict) -> bytes:
    assert set(case.keys()) in (
        {"name", "trusted_network_id", "wire_hex", "statement_digest_hex"},
        {"name", "trusted_network_id", "wire_hex"},
    )
    return bytes.fromhex(case["wire_hex"])


def test_shared_valid_vectors_have_exact_bytes_and_digests() -> None:
    corpus = _corpus()
    assert len(corpus["valid_cases"]) == 8
    names = set()
    digests = set()

    for case in corpus["valid_cases"]:
        assert case["name"] not in names
        names.add(case["name"])
        wire = _wire(case)
        assert len(wire) <= MAX_CANONICAL_V2_STATEMENT_BYTES

        statement = ThreatHintV2Statement.parse_canonical(
            wire, case["trusted_network_id"]
        )
        assert statement.canonical_bytes == wire
        assert statement.statement_digest().hex() == case["statement_digest_hex"]
        assert case["statement_digest_hex"] not in digests
        digests.add(case["statement_digest_hex"])


def test_every_bound_field_changes_the_statement_digest() -> None:
    cases = {case["name"]: case for case in _corpus()["valid_cases"]}
    base_digest = cases["base_review_required"]["statement_digest_hex"]

    for changed_name in (
        "artifact_hash_changed",
        "observable_commitment_changed",
        "confidence_changed",
        "disclosure_class_changed",
        "report_nonce_changed",
        "observed_at_changed",
        "network_changed",
    ):
        assert cases[changed_name]["statement_digest_hex"] != base_digest


def test_shared_invalid_vectors_fail_closed_with_one_error() -> None:
    cases = _corpus()["invalid_cases"]
    assert len(cases) >= 20
    names = set()

    for case in cases:
        assert case["name"] not in names
        names.add(case["name"])
        with pytest.raises(
            ThreatHintV2StatementError,
            match=r"^invalid threat-hint v2 statement$",
        ):
            ThreatHintV2Statement.parse_canonical(
                _wire(case), case["trusted_network_id"]
            )


def test_parsed_fields_preserve_closed_structural_values() -> None:
    cases = {case["name"]: case for case in _corpus()["valid_cases"]}
    review_case = cases["base_review_required"]
    public_case = cases["disclosure_class_changed"]
    review = ThreatHintV2Statement.parse_canonical(
        _wire(review_case), review_case["trusted_network_id"]
    )
    public = ThreatHintV2Statement.parse_canonical(
        _wire(public_case), public_case["trusted_network_id"]
    )

    assert review.schema_version == 2
    assert review.artifact_hash == "00" * 32
    assert review.observable_commitment == "11" * 32
    assert review.confidence_bps == 7500
    assert review.disclosure_class is ThreatHintV2DisclosureClass.REVIEW_REQUIRED_V1
    assert review.report_nonce == "22" * 32
    assert review.observed_at == 1_700_000_000
    assert review.network_id == "testnet-10"
    assert public.disclosure_class is ThreatHintV2DisclosureClass.PUBLIC_AUTO_V1


def test_direct_subclass_and_nonbytes_construction_are_rejected() -> None:
    case = _corpus()["valid_cases"][0]
    wire = _wire(case)

    with pytest.raises(TypeError):
        ThreatHintV2Statement()
    with pytest.raises(ThreatHintV2StatementError):
        ThreatHintV2Statement.parse_canonical(
            bytearray(wire), case["trusted_network_id"]  # type: ignore[arg-type]
        )

    class ForgedStatement(ThreatHintV2Statement):
        """Adversarial parser subclass used to test exact-type enforcement."""

    with pytest.raises(ThreatHintV2StatementError):
        ForgedStatement.parse_canonical(wire, case["trusted_network_id"])


def test_valid_shape_mutation_cannot_serialize_or_digest() -> None:
    case = _corpus()["valid_cases"][0]
    statement = ThreatHintV2Statement.parse_canonical(
        _wire(case), case["trusted_network_id"]
    )
    object.__setattr__(statement, "artifact_hash", "ff" * 32)

    with pytest.raises(ThreatHintV2StatementError):
        _ = statement.canonical_bytes
    with pytest.raises(ThreatHintV2StatementError):
        statement.statement_digest()


def test_manually_forged_valid_shape_instance_cannot_serialize_or_digest() -> None:
    case = _corpus()["valid_cases"][0]
    parsed = ThreatHintV2Statement.parse_canonical(
        _wire(case), case["trusted_network_id"]
    )
    forged = object.__new__(ThreatHintV2Statement)
    for field_name in (
        "schema_version",
        "artifact_hash",
        "observable_commitment",
        "confidence_bps",
        "disclosure_class",
        "report_nonce",
        "observed_at",
        "network_id",
    ):
        object.__setattr__(forged, field_name, getattr(parsed, field_name))

    with pytest.raises(ThreatHintV2StatementError):
        _ = forged.canonical_bytes
    with pytest.raises(ThreatHintV2StatementError):
        forged.statement_digest()


def test_oversized_input_and_invalid_trusted_network_are_rejected() -> None:
    case = _corpus()["valid_cases"][0]
    with pytest.raises(ThreatHintV2StatementError):
        ThreatHintV2Statement.parse_canonical(
            b"{" * (MAX_CANONICAL_V2_STATEMENT_BYTES + 1), "testnet-10"
        )
    with pytest.raises(ThreatHintV2StatementError):
        ThreatHintV2Statement.parse_canonical(_wire(case), "-testnet-10")
    with pytest.raises(ThreatHintV2StatementError):
        ThreatHintV2Statement.parse_canonical(_wire(case), 10)  # type: ignore[arg-type]


def test_statement_digest_is_separate_from_bundle_and_approval_domains() -> None:
    case = _corpus()["valid_cases"][0]
    wire = _wire(case)
    statement = ThreatHintV2Statement.parse_canonical(wire, case["trusted_network_id"])

    def digest(domain: bytes) -> bytes:
        return hashlib.sha256(
            domain + len(wire).to_bytes(4, byteorder="big") + wire
        ).digest()

    assert statement.statement_digest() == digest(STATEMENT_DIGEST_DOMAIN)
    assert statement.statement_digest() != digest(
        b"prometheus-threat-observable-bundle-v1\x00"
    )
    assert statement.statement_digest() != digest(
        b"prometheus-observable-approval-v1\x00"
    )
