"""Parity and security tests for the canonical endpoint observation statement."""

# Pytest test names provide scenario descriptions.
# pylint: disable=missing-function-docstring

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable

import pytest

from jaeger.endpoint_observation import (
    MAX_CANONICAL_ENDPOINT_OBSERVATION_BYTES,
    STATEMENT_DIGEST_DOMAIN,
    EndpointObservationDomain,
    EndpointObservationError,
    EndpointObservationSignal,
    EndpointObservationStatementV1,
)

VECTOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "threat-hint"
    / "tests"
    / "vectors"
    / "endpoint-observation-v1.json"
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


def test_shared_valid_vectors_match_exact_bytes_and_digests() -> None:
    cases = _corpus()["valid_cases"]
    assert len(cases) == 20
    names = set()
    digests = set()
    for case in cases:
        assert case["name"] not in names
        names.add(case["name"])
        wire = _wire(case)
        assert len(wire) <= MAX_CANONICAL_ENDPOINT_OBSERVATION_BYTES
        statement = EndpointObservationStatementV1.parse_canonical(
            wire, case["trusted_network_id"]
        )
        assert statement.canonical_bytes == wire
        assert statement.statement_digest().hex() == case["statement_digest_hex"]
        assert case["statement_digest_hex"] not in digests
        digests.add(case["statement_digest_hex"])


def test_shared_invalid_vectors_fail_with_one_redacted_error() -> None:
    cases = _corpus()["invalid_cases"]
    assert len(cases) == 42
    names = set()
    for case in cases:
        assert case["name"] not in names
        names.add(case["name"])
        with pytest.raises(
            EndpointObservationError,
            match=r"^invalid endpoint observation statement$",
        ):
            EndpointObservationStatementV1.parse_canonical(
                _wire(case), case["trusted_network_id"]
            )


def test_all_signals_match_their_closed_domain() -> None:
    expected = {signal.value: signal.domain for signal in EndpointObservationSignal}
    observed = {}
    for case in _corpus()["valid_cases"][:15]:
        statement = EndpointObservationStatementV1.parse_canonical(
            _wire(case), case["trusted_network_id"]
        )
        observed[statement.signal.value] = statement.domain
        assert statement.signal.domain is statement.domain
    assert observed == expected
    assert set(observed.values()) == set(EndpointObservationDomain)


def test_every_mutable_field_is_digest_bound() -> None:
    cases = {case["name"]: case for case in _corpus()["valid_cases"]}
    base = cases["base_process_unexpected_child_process"]["statement_digest_hex"]
    for name in (
        "signal_rapid_process_spawn",
        "signal_protected_file_change",
        "event_count_changed",
        "window_seconds_changed",
        "report_nonce_changed",
        "observed_at_changed",
        "network_changed",
    ):
        assert cases[name]["statement_digest_hex"] != base


def test_parsed_fields_are_closed_and_bounded() -> None:
    case = _corpus()["valid_cases"][0]
    statement = EndpointObservationStatementV1.parse_canonical(
        _wire(case), case["trusted_network_id"]
    )
    assert statement.schema_version == 1
    assert statement.domain is EndpointObservationDomain.PROCESS
    assert statement.signal is EndpointObservationSignal.UNEXPECTED_CHILD_PROCESS
    assert statement.event_count == 1
    assert statement.window_seconds == 60
    assert statement.report_nonce == "aa" * 32
    assert statement.observed_at == 1_700_000_040
    assert statement.network_id == "testnet-10"


def test_direct_subclass_and_nonbytes_construction_are_rejected() -> None:
    case = _corpus()["valid_cases"][0]
    wire = _wire(case)
    with pytest.raises(TypeError):
        EndpointObservationStatementV1()
    with pytest.raises(EndpointObservationError):
        EndpointObservationStatementV1.parse_canonical(  # type: ignore[arg-type]
            bytearray(wire), case["trusted_network_id"]
        )

    class ForgedObservation(EndpointObservationStatementV1):
        """Adversarial parser subclass used to test exact-type enforcement."""

    with pytest.raises(EndpointObservationError):
        ForgedObservation.parse_canonical(wire, case["trusted_network_id"])


def test_mutated_or_forged_instances_have_no_authority() -> None:
    case = _corpus()["valid_cases"][0]
    parsed = EndpointObservationStatementV1.parse_canonical(
        _wire(case), case["trusted_network_id"]
    )
    object.__setattr__(parsed, "event_count", 2)
    with pytest.raises(EndpointObservationError):
        _ = parsed.canonical_bytes
    with pytest.raises(EndpointObservationError):
        parsed.statement_digest()

    fresh = EndpointObservationStatementV1.parse_canonical(
        _wire(case), case["trusted_network_id"]
    )
    forged = object.__new__(EndpointObservationStatementV1)
    for field_name in (
        "schema_version",
        "domain",
        "signal",
        "event_count",
        "window_seconds",
        "report_nonce",
        "observed_at",
        "network_id",
    ):
        object.__setattr__(forged, field_name, getattr(fresh, field_name))
    with pytest.raises(EndpointObservationError):
        _ = forged.canonical_bytes


def test_digest_domain_is_independent() -> None:
    case = _corpus()["valid_cases"][0]
    wire = _wire(case)
    statement = EndpointObservationStatementV1.parse_canonical(
        wire, case["trusted_network_id"]
    )

    def digest(domain: bytes) -> bytes:
        return hashlib.sha256(
            domain + len(wire).to_bytes(4, byteorder="big") + wire
        ).digest()

    assert statement.statement_digest() == digest(STATEMENT_DIGEST_DOMAIN)
    assert statement.statement_digest() != digest(
        b"prometheus-threat-hint-statement-v2\x00"
    )
