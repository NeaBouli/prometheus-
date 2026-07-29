"""Parity and security tests for the local canonical RelationManifest-v2."""

# Pytest test names provide the scenario descriptions.
# pylint: disable=missing-function-docstring

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable

import pytest

from jaeger.relation_manifest_v2 import (
    ARKWORKS_VERSION,
    KIP16_STATUS_COMMIT,
    KIP16_TAG,
    MAX_CANONICAL_V2_MANIFEST_BYTES,
    MAX_PROVING_KEY_BYTES,
    MAX_RELATION_SOURCE_BYTES,
    MAX_VERIFYING_KEY_BYTES,
    PROTOCOL_ID,
    PROOF_SYSTEM,
    PUBLIC_INPUT_COUNT,
    PUBLIC_INPUT_ENCODING,
    RELATION_ID,
    RUSTY_KASPA_COMMIT,
    RUSTY_KASPA_TAG,
    SCHEMA_VERSION,
    STATEMENT_DIGEST_DOMAIN_HEX,
    RelationManifestV2,
    RelationManifestV2Error,
)

VECTOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "threat-proof"
    / "tests"
    / "vectors"
    / "relation-manifest-v2-v1.json"
)

VALID_VECTOR_COUNT = 5
INVALID_VECTOR_COUNT = 56


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
    assert parsed["statement_digest_domain_hex"] == STATEMENT_DIGEST_DOMAIN_HEX
    return parsed


def _wire(case: dict) -> bytes:
    assert set(case.keys()) in (
        {"name", "trusted_network_id", "wire_hex", "manifest_sha256_hex"},
        {"name", "trusted_network_id", "wire_hex"},
    )
    return bytes.fromhex(case["wire_hex"])


def _valid_case(name: str) -> dict:
    cases = {case["name"]: case for case in _corpus()["valid_cases"]}
    return cases[name]


def test_constant_pins_match_the_exact_schema() -> None:
    assert SCHEMA_VERSION == 2
    assert PROTOCOL_ID == "/prometheus/threat-hint/2.0.0"
    assert RELATION_ID == "prometheus-threat-hint-v2"
    assert (
        bytes.fromhex(STATEMENT_DIGEST_DOMAIN_HEX)
        == b"prometheus-threat-hint-statement-v2\x00"
    )
    assert PROOF_SYSTEM == "groth16_bn254_kip16"
    assert KIP16_TAG == 32
    assert PUBLIC_INPUT_ENCODING == "sha256_split_u128_bn254_v2"
    assert PUBLIC_INPUT_COUNT == 2
    assert MAX_RELATION_SOURCE_BYTES == 1_048_576
    assert MAX_PROVING_KEY_BYTES == 1_073_741_824
    assert MAX_VERIFYING_KEY_BYTES == 65_536
    assert MAX_CANONICAL_V2_MANIFEST_BYTES == 4096
    assert KIP16_STATUS_COMMIT == "e4ae2332117b5cb68bd6188e065ef885b6d17939"
    assert RUSTY_KASPA_TAG == "v2.0.1"
    assert RUSTY_KASPA_COMMIT == "cfafeb4c093fa37a303f1b9f19c58f986b870ce3"
    assert ARKWORKS_VERSION == "0.6.0"


def test_shared_valid_vectors_have_exact_bytes_and_manifest_digests() -> None:
    corpus = _corpus()
    assert len(corpus["valid_cases"]) == VALID_VECTOR_COUNT
    names = set()
    digests = set()

    for case in corpus["valid_cases"]:
        assert case["name"] not in names
        names.add(case["name"])
        wire = _wire(case)
        assert 1 <= len(wire) <= MAX_CANONICAL_V2_MANIFEST_BYTES

        manifest = RelationManifestV2.parse_canonical(wire, case["trusted_network_id"])
        assert manifest.canonical_bytes == wire
        assert hashlib.sha256(wire).hexdigest() == case["manifest_sha256_hex"]
        assert case["manifest_sha256_hex"] not in digests
        digests.add(case["manifest_sha256_hex"])


def test_parsed_fields_preserve_closed_schema_values() -> None:
    base = _valid_case("base_testnet")
    manifest = RelationManifestV2.parse_canonical(
        _wire(base), base["trusted_network_id"]
    )

    assert manifest.schema_version == 2
    assert manifest.protocol_id == "/prometheus/threat-hint/2.0.0"
    assert manifest.relation_id == "prometheus-threat-hint-v2"
    assert manifest.statement_digest_domain_hex == STATEMENT_DIGEST_DOMAIN_HEX
    assert manifest.proof_system == "groth16_bn254_kip16"
    assert manifest.kip16_tag == 32
    assert manifest.public_input_encoding == "sha256_split_u128_bn254_v2"
    assert manifest.public_input_count == 2
    assert manifest.network_id == "testnet-10"
    assert manifest.relation_source_bytes == 4096
    assert manifest.relation_source_sha256 == "11" * 32
    assert manifest.proving_key_bytes == 1_048_576
    assert manifest.proving_key_sha256 == "22" * 32
    assert manifest.verifying_key_bytes == 1024
    assert manifest.verifying_key_sha256 == "33" * 32
    assert manifest.kip16_status_commit == KIP16_STATUS_COMMIT
    assert manifest.rusty_kaspa_tag == RUSTY_KASPA_TAG
    assert manifest.rusty_kaspa_commit == RUSTY_KASPA_COMMIT
    assert manifest.arkworks_version == ARKWORKS_VERSION

    minimum = _valid_case("min_byte_bounds")
    min_manifest = RelationManifestV2.parse_canonical(
        _wire(minimum), minimum["trusted_network_id"]
    )
    assert min_manifest.relation_source_bytes == 1
    assert min_manifest.proving_key_bytes == 1
    assert min_manifest.verifying_key_bytes == 1

    maximum = _valid_case("max_byte_bounds")
    max_manifest = RelationManifestV2.parse_canonical(
        _wire(maximum), maximum["trusted_network_id"]
    )
    assert max_manifest.relation_source_bytes == MAX_RELATION_SOURCE_BYTES
    assert max_manifest.proving_key_bytes == MAX_PROVING_KEY_BYTES
    assert max_manifest.verifying_key_bytes == MAX_VERIFYING_KEY_BYTES


def test_shared_invalid_vectors_fail_closed_with_one_error() -> None:
    cases = _corpus()["invalid_cases"]
    assert len(cases) == INVALID_VECTOR_COUNT
    names = set()

    for case in cases:
        assert case["name"] not in names
        names.add(case["name"])
        with pytest.raises(
            RelationManifestV2Error,
            match=r"^invalid relation manifest v2$",
        ):
            RelationManifestV2.parse_canonical(_wire(case), case["trusted_network_id"])


def test_canonical_v1_shaped_manifest_is_rejected() -> None:
    cases = {case["name"]: case for case in _corpus()["invalid_cases"]}
    v1_case = cases["v1_manifest_confusion"]
    decoded = json.loads(_wire(v1_case).decode("utf-8"))
    assert decoded["schema_version"] == 1
    assert decoded["verification_domain"] == "prometheus-threat-hint-v1"

    with pytest.raises(RelationManifestV2Error):
        RelationManifestV2.parse_canonical(
            _wire(v1_case), v1_case["trusted_network_id"]
        )


def test_direct_subclass_and_nonbytes_construction_are_rejected() -> None:
    case = _valid_case("base_testnet")
    wire = _wire(case)

    with pytest.raises(TypeError):
        RelationManifestV2()
    with pytest.raises(RelationManifestV2Error):
        RelationManifestV2.parse_canonical(
            bytearray(wire), case["trusted_network_id"]  # type: ignore[arg-type]
        )

    class ForgedManifest(RelationManifestV2):
        """Adversarial parser subclass used to test exact-type enforcement."""

    with pytest.raises(RelationManifestV2Error):
        ForgedManifest.parse_canonical(wire, case["trusted_network_id"])


def test_valid_shape_mutation_cannot_serialize() -> None:
    case = _valid_case("base_testnet")
    manifest = RelationManifestV2.parse_canonical(
        _wire(case), case["trusted_network_id"]
    )
    object.__setattr__(manifest, "relation_source_sha256", "ff" * 32)

    with pytest.raises(RelationManifestV2Error):
        _ = manifest.canonical_bytes


def test_manually_forged_valid_shape_instance_cannot_serialize() -> None:
    case = _valid_case("base_testnet")
    parsed = RelationManifestV2.parse_canonical(_wire(case), case["trusted_network_id"])
    forged = object.__new__(RelationManifestV2)
    for field_name in (
        "schema_version",
        "protocol_id",
        "relation_id",
        "statement_digest_domain_hex",
        "proof_system",
        "kip16_tag",
        "public_input_encoding",
        "public_input_count",
        "network_id",
        "relation_source_bytes",
        "relation_source_sha256",
        "proving_key_bytes",
        "proving_key_sha256",
        "verifying_key_bytes",
        "verifying_key_sha256",
        "kip16_status_commit",
        "rusty_kaspa_tag",
        "rusty_kaspa_commit",
        "arkworks_version",
    ):
        object.__setattr__(forged, field_name, getattr(parsed, field_name))

    with pytest.raises(RelationManifestV2Error):
        _ = forged.canonical_bytes


def test_oversized_input_and_invalid_trusted_network_are_rejected() -> None:
    case = _valid_case("base_testnet")
    with pytest.raises(RelationManifestV2Error):
        RelationManifestV2.parse_canonical(
            b"{" * (MAX_CANONICAL_V2_MANIFEST_BYTES + 1), "testnet-10"
        )
    with pytest.raises(RelationManifestV2Error):
        RelationManifestV2.parse_canonical(_wire(case), "-testnet-10")
    with pytest.raises(RelationManifestV2Error):
        RelationManifestV2.parse_canonical(_wire(case), 10)  # type: ignore[arg-type]
