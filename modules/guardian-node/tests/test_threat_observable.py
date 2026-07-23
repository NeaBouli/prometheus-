"""Tests for canonical Threat Observable Bundle v1 parsing and commitments."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from jaeger.threat_observable import (
    DisclosurePolicy,
    MAX_CANONICAL_BYTES,
    Observable,
    ObservableBundle,
    ObservableBundleError,
    ObservableKind,
    ObservableScope,
    ScopeFormat,
    ScopePlatform,
)

_VECTOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "threat-hint"
    / "tests"
    / "vectors"
    / "threat-observable-bundle-v1.json"
)
_PRODUCER_VECTOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "threat-hint"
    / "tests"
    / "vectors"
    / "threat-observable-file-sha256-producer-v1.json"
)


def _unique_object(items: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in items:
        assert key not in result, f"duplicate fixture key: {key}"
        result[key] = value
    return result


def _load_vector() -> dict:
    raw = _VECTOR_PATH.read_text(encoding="utf-8")
    parsed = json.loads(raw, object_pairs_hook=_unique_object)

    assert set(parsed.keys()) == {
        "vector_schema_version",
        "valid_cases",
        "invalid_bundle_cases",
        "invalid_commitment_cases",
    }
    assert type(parsed["vector_schema_version"]) is int
    assert parsed["vector_schema_version"] == 1
    assert isinstance(parsed["valid_cases"], list)
    assert isinstance(parsed["invalid_bundle_cases"], list)
    assert isinstance(parsed["invalid_commitment_cases"], list)

    names = [
        case["name"]
        for case in parsed["valid_cases"]
        + parsed["invalid_bundle_cases"]
        + parsed["invalid_commitment_cases"]
    ]
    assert len(names) == len(set(names))
    return parsed


def _wire_from_hex(wire_hex: str) -> bytes:
    return bytes.fromhex(wire_hex)


def _canonical_wire(vector: dict, case_name: str) -> bytes:
    for case in vector["valid_cases"]:
        if case["name"] == case_name:
            return _wire_from_hex(case["wire_hex"])
    raise AssertionError(f"missing {case_name}")


@pytest.fixture(scope="module")
def vector() -> dict:
    return _load_vector()


def test_vector_top_level_and_names(vector: dict) -> None:
    for case in vector["valid_cases"]:
        assert set(case.keys()) == {
            "name",
            "wire_hex",
            "network_id",
            "report_nonce_hex",
            "commitment_hex",
        }
        assert all(type(value) is str for value in case.values())

    for case in vector["invalid_bundle_cases"]:
        assert set(case.keys()) == {"name", "wire_hex"}
        assert all(type(value) is str for value in case.values())

    for case in vector["invalid_commitment_cases"]:
        assert set(case.keys()) == {
            "name",
            "wire_hex",
            "network_id",
            "report_nonce_hex",
        }
        assert all(type(value) is str for value in case.values())


def test_vector_unique_case_names(vector: dict) -> None:
    names = [
        case["name"]
        for case in vector["valid_cases"]
        + vector["invalid_bundle_cases"]
        + vector["invalid_commitment_cases"]
    ]
    assert len(names) == len(set(names))


def test_valid_bundles_and_commitments(vector: dict) -> None:
    for case in vector["valid_cases"]:
        wire = _wire_from_hex(case["wire_hex"])
        bundle = ObservableBundle.parse_canonical(wire)
        assert bundle.canonical_bytes == wire
        commitment = bundle.commitment(case["network_id"], case["report_nonce_hex"])
        assert commitment == bytes.fromhex(case["commitment_hex"])
        assert ObservableBundle.commitment_matches(
            bytes.fromhex(case["commitment_hex"]),
            case["network_id"],
            case["report_nonce_hex"],
            wire,
        )


def test_invalid_bundle_cases(vector: dict) -> None:
    for case in vector["invalid_bundle_cases"]:
        wire = _wire_from_hex(case["wire_hex"])
        with pytest.raises(ObservableBundleError):
            ObservableBundle.parse_canonical(wire)


def test_invalid_commitment_cases(vector: dict) -> None:
    for case in vector["invalid_commitment_cases"]:
        wire = _wire_from_hex(case["wire_hex"])
        bundle = ObservableBundle.parse_canonical(wire)
        with pytest.raises(ObservableBundleError):
            bundle.commitment(case["network_id"], case["report_nonce_hex"])


def test_commitment_mismatch_returns_false(vector: dict) -> None:
    case = next(
        case for case in vector["valid_cases"] if case["name"] == "public_api_import"
    )
    wire = _wire_from_hex(case["wire_hex"])
    expected = bytes.fromhex(case["commitment_hex"])
    tampered = bytes([expected[0] ^ 0xFF]) + expected[1:]

    assert (
        ObservableBundle.commitment_matches(
            tampered,
            case["network_id"],
            case["report_nonce_hex"],
            wire,
        )
        is False
    )


def test_commitment_expected_length_rejection(vector: dict) -> None:
    wire = _canonical_wire(vector, "public_api_import")
    case = next(
        case for case in vector["valid_cases"] if case["name"] == "public_api_import"
    )

    with pytest.raises(ObservableBundleError):
        ObservableBundle.commitment_matches(
            b"\x00" * 31,
            case["network_id"],
            case["report_nonce_hex"],
            wire,
        )

    with pytest.raises(ObservableBundleError):
        ObservableBundle.commitment_matches(
            b"\x00" * 33,
            case["network_id"],
            case["report_nonce_hex"],
            wire,
        )


def test_rejected_value_error_is_redacted(vector: dict) -> None:
    case = next(
        case
        for case in vector["invalid_bundle_cases"]
        if case["name"] == "observable_api_import_bad_char"
    )
    wire = _wire_from_hex(case["wire_hex"])

    with pytest.raises(ObservableBundleError) as exc_info:
        ObservableBundle.parse_canonical(wire)

    message = str(exc_info.value)
    assert "bad$name" not in message


def test_byte_pattern_too_many_tokens(vector: dict) -> None:
    del vector
    tokens = ["aa"] * 65
    wire = (
        b'{"schema_version":1,"disclosure_policy":"review_required_v1",'
        b'"scope":{"platform":"linux","format":"elf"},'
        b'"observables":[{"kind":"byte_pattern","value":"'
        + " ".join(tokens).encode("ascii")
        + b'"}]}'
    )

    with pytest.raises(ObservableBundleError):
        ObservableBundle.parse_canonical(wire)


def test_bundle_bytes_limit(vector: dict) -> None:
    del vector
    wire = b"{" + b"a" * (MAX_CANONICAL_BYTES + 1)
    with pytest.raises(ObservableBundleError):
        ObservableBundle.parse_canonical(wire)


@pytest.mark.parametrize("bundle_type", [ObservableScope, Observable, ObservableBundle])
def test_direct_construction_is_disabled(bundle_type: type) -> None:
    with pytest.raises(TypeError):
        bundle_type()


def test_parser_requires_exact_bytes(vector: dict) -> None:
    wire = _canonical_wire(vector, "public_api_import")
    with pytest.raises(ObservableBundleError):
        ObservableBundle.parse_canonical(bytearray(wire))


def test_mutated_frozen_bundle_cannot_serialize_or_commit(vector: dict) -> None:
    case = next(
        case for case in vector["valid_cases"] if case["name"] == "public_api_import"
    )
    bundle = ObservableBundle.parse_canonical(_wire_from_hex(case["wire_hex"]))
    object.__setattr__(bundle, "observables", ())

    with pytest.raises(ObservableBundleError):
        _ = bundle.canonical_bytes
    with pytest.raises(ObservableBundleError):
        bundle.commitment(case["network_id"], case["report_nonce_hex"])


def test_observable_grammar_precedes_disclosure_policy() -> None:
    wire = (
        b'{"schema_version":1,"disclosure_policy":"public_auto_v1",'
        b'"scope":{"platform":"linux","format":"elf"},'
        b'"observables":[{"kind":"byte_pattern","value":"aa"}]}'
    )
    with pytest.raises(ObservableBundleError) as exc_info:
        ObservableBundle.parse_canonical(wire)

    assert str(exc_info.value) == "invalid observable"


def test_rust_file_sha256_producer_vectors_validate_independently() -> None:
    raw = _PRODUCER_VECTOR_PATH.read_text(encoding="utf-8")
    producer_vectors = json.loads(raw, object_pairs_hook=_unique_object)

    assert set(producer_vectors.keys()) == {"vector_schema_version", "cases"}
    assert producer_vectors["vector_schema_version"] == 1
    assert len(producer_vectors["cases"]) >= 3

    names = set()
    for case in producer_vectors["cases"]:
        assert set(case.keys()) == {
            "name",
            "artifact_hex",
            "platform",
            "format",
            "file_sha256",
            "wire_hex",
        }
        assert case["name"] not in names
        names.add(case["name"])

        artifact = bytes.fromhex(case["artifact_hex"])
        wire = bytes.fromhex(case["wire_hex"])
        assert artifact.hex() == case["artifact_hex"]
        assert wire.hex() == case["wire_hex"]

        expected_digest = hashlib.sha256(artifact).hexdigest()
        assert expected_digest == case["file_sha256"]

        bundle = ObservableBundle.parse_canonical(wire)
        assert bundle.canonical_bytes == wire
        assert bundle.disclosure_policy == DisclosurePolicy.PUBLIC_AUTO_V1
        assert bundle.scope.platform == ScopePlatform(case["platform"])
        assert bundle.scope.format == ScopeFormat(case["format"])
        assert len(bundle.observables) == 1
        assert bundle.observables[0].kind == ObservableKind.FILE_SHA256
        assert bundle.observables[0].value == expected_digest
