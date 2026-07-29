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
_BYTE_PATTERN_PRODUCER_VECTOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "threat-hint"
    / "tests"
    / "vectors"
    / "threat-observable-byte-pattern-producer-v1.json"
)
_ELF_API_IMPORT_PRODUCER_VECTOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "threat-hint"
    / "tests"
    / "vectors"
    / "threat-observable-elf-api-import-producer-v1.json"
)
_PE_API_IMPORT_PRODUCER_VECTOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "threat-hint"
    / "tests"
    / "vectors"
    / "threat-observable-pe-api-import-producer-v1.json"
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


def test_rust_byte_pattern_producer_vectors_validate_independently() -> None:
    raw = _BYTE_PATTERN_PRODUCER_VECTOR_PATH.read_text(encoding="utf-8")
    producer_vectors = json.loads(raw, object_pairs_hook=_unique_object)

    assert set(producer_vectors.keys()) == {"vector_schema_version", "cases"}
    assert producer_vectors["vector_schema_version"] == 1
    assert len(producer_vectors["cases"]) >= 3

    names = set()
    for case in producer_vectors["cases"]:
        assert set(case.keys()) == {
            "name",
            "artifact_hex",
            "start",
            "wildcard_mask",
            "platform",
            "format",
            "byte_pattern",
            "wire_hex",
        }
        assert case["name"] not in names
        names.add(case["name"])
        assert type(case["start"]) is int
        assert case["start"] >= 0
        assert isinstance(case["wildcard_mask"], list)
        assert all(type(wildcard) is bool for wildcard in case["wildcard_mask"])
        assert 8 <= len(case["wildcard_mask"]) <= 64
        assert sum(not wildcard for wildcard in case["wildcard_mask"]) >= 8

        artifact = bytes.fromhex(case["artifact_hex"])
        wire = bytes.fromhex(case["wire_hex"])
        assert artifact.hex() == case["artifact_hex"]
        assert wire.hex() == case["wire_hex"]

        end = case["start"] + len(case["wildcard_mask"])
        assert end <= len(artifact)
        selected = artifact[case["start"] : end]
        expected_pattern = " ".join(
            "??" if wildcard else f"{byte:02x}"
            for byte, wildcard in zip(selected, case["wildcard_mask"], strict=True)
        )
        assert expected_pattern == case["byte_pattern"]

        bundle = ObservableBundle.parse_canonical(wire)
        assert bundle.canonical_bytes == wire
        assert bundle.disclosure_policy == DisclosurePolicy.REVIEW_REQUIRED_V1
        assert bundle.scope.platform == ScopePlatform(case["platform"])
        assert bundle.scope.format == ScopeFormat(case["format"])
        assert len(bundle.observables) == 1
        assert bundle.observables[0].kind == ObservableKind.BYTE_PATTERN
        assert bundle.observables[0].value == expected_pattern


def _read_test_elf_integer(artifact: bytes, offset: int, size: int) -> int:
    return int.from_bytes(artifact[offset : offset + size], "little")


def _parse_test_elf64_sections(artifact: bytes) -> list[dict[str, int]]:
    assert artifact[:7] == b"\x7fELF\x02\x01\x01"
    section_headers_offset = _read_test_elf_integer(artifact, 40, 8)
    section_header_size = _read_test_elf_integer(artifact, 58, 2)
    section_count = _read_test_elf_integer(artifact, 60, 2)
    assert section_header_size == 64
    assert section_headers_offset + section_header_size * section_count <= len(artifact)

    sections = []
    for index in range(section_count):
        start = section_headers_offset + index * section_header_size
        sections.append(
            {
                "type": _read_test_elf_integer(artifact, start + 4, 4),
                "offset": _read_test_elf_integer(artifact, start + 24, 8),
                "size": _read_test_elf_integer(artifact, start + 32, 8),
                "link": _read_test_elf_integer(artifact, start + 40, 4),
                "entry_size": _read_test_elf_integer(artifact, start + 56, 8),
            }
        )
    return sections


def _extract_test_elf64_dynamic_imports(artifact: bytes) -> list[str]:
    sections = _parse_test_elf64_sections(artifact)
    dynamic_symbols = next(section for section in sections if section["type"] == 11)
    dynamic_strings = sections[dynamic_symbols["link"]]
    assert dynamic_strings["type"] == 3
    assert dynamic_symbols["entry_size"] == 24

    strings_start = dynamic_strings["offset"]
    strings_end = strings_start + dynamic_strings["size"]
    symbols_start = dynamic_symbols["offset"]
    symbols_end = symbols_start + dynamic_symbols["size"]
    assert strings_end <= len(artifact)
    assert symbols_end <= len(artifact)

    names = []
    for start in range(
        symbols_start + dynamic_symbols["entry_size"],
        symbols_end,
        dynamic_symbols["entry_size"],
    ):
        name_offset = _read_test_elf_integer(artifact, start, 4)
        section_index = _read_test_elf_integer(artifact, start + 6, 2)
        if section_index != 0 or name_offset == 0:
            continue
        name_start = strings_start + name_offset
        name_end = artifact.index(b"\x00", name_start, strings_end)
        names.append(artifact[name_start:name_end].decode("ascii"))

    return sorted(set(names), key=lambda name: name.encode("ascii"))


def test_rust_elf_api_import_producer_vectors_validate_independently() -> None:
    raw = _ELF_API_IMPORT_PRODUCER_VECTOR_PATH.read_text(encoding="utf-8")
    producer_vectors = json.loads(raw, object_pairs_hook=_unique_object)

    assert set(producer_vectors.keys()) == {
        "vector_schema_version",
        "artifact_sha256",
        "artifact_hex",
        "cases",
    }
    assert producer_vectors["vector_schema_version"] == 1
    assert len(producer_vectors["cases"]) >= 3

    artifact = bytes.fromhex(producer_vectors["artifact_hex"])
    assert hashlib.sha256(artifact).hexdigest() == producer_vectors["artifact_sha256"]
    imports = _extract_test_elf64_dynamic_imports(artifact)
    assert imports == ["close", "mmap", "pthread_create"]

    names = set()
    for case in producer_vectors["cases"]:
        assert set(case.keys()) == {
            "name",
            "import_index",
            "api_import",
            "wire_hex",
        }
        assert case["name"] not in names
        names.add(case["name"])
        assert isinstance(case["import_index"], int)
        assert not isinstance(case["import_index"], bool)
        assert imports[case["import_index"]] == case["api_import"]

        wire = bytes.fromhex(case["wire_hex"])
        bundle = ObservableBundle.parse_canonical(wire)
        assert bundle.canonical_bytes == wire
        assert bundle.disclosure_policy == DisclosurePolicy.REVIEW_REQUIRED_V1
        assert bundle.scope.platform == ScopePlatform.LINUX
        assert bundle.scope.format == ScopeFormat.ELF
        assert len(bundle.observables) == 1
        assert bundle.observables[0].kind == ObservableKind.API_IMPORT
        assert bundle.observables[0].value == case["api_import"]


def _read_test_pe_cstring(artifact: bytes, offset: int, section_end: int) -> bytes:
    """Read one nonempty ASCII C string from the bounded synthetic PE section."""
    assert offset < section_end
    end = artifact.index(b"\x00", offset, section_end)
    value = artifact[offset:end]
    assert value
    value.decode("ascii")
    return value


def _extract_test_pe32_plus_imports(artifact: bytes) -> list[str]:
    """Parses exactly the synthetic single-section PE32+ fixture form."""
    assert len(artifact) >= 512
    assert artifact[:2] == b"MZ"
    pe_offset = _read_test_elf_integer(artifact, 0x3C, 4)
    assert pe_offset == 64
    assert artifact[pe_offset : pe_offset + 4] == b"PE\x00\x00"

    coff = pe_offset + 4
    assert _read_test_elf_integer(artifact, coff, 2) == 0x8664
    section_count = _read_test_elf_integer(artifact, coff + 2, 2)
    assert section_count == 1
    optional_size = _read_test_elf_integer(artifact, coff + 16, 2)
    assert optional_size == 240

    optional = coff + 20
    assert _read_test_elf_integer(artifact, optional, 2) == 0x20B
    assert _read_test_elf_integer(artifact, optional + 108, 4) == 16
    import_rva = _read_test_elf_integer(artifact, optional + 120, 4)
    import_size = _read_test_elf_integer(artifact, optional + 124, 4)
    assert import_size == 40

    section_header = optional + optional_size
    assert section_header + 40 <= len(artifact)
    assert artifact[section_header : section_header + 8] == b".idata\x00\x00"
    virtual_size = _read_test_elf_integer(artifact, section_header + 8, 4)
    virtual_address = _read_test_elf_integer(artifact, section_header + 12, 4)
    raw_size = _read_test_elf_integer(artifact, section_header + 16, 4)
    raw_offset = _read_test_elf_integer(artifact, section_header + 20, 4)
    assert import_rva == virtual_address
    assert virtual_size == raw_size
    assert raw_offset == 512
    assert raw_offset + raw_size == len(artifact)
    section_end = raw_offset + raw_size

    def rva_to_offset(rva: int) -> int:
        assert virtual_address <= rva < virtual_address + virtual_size
        return raw_offset + (rva - virtual_address)

    names = []
    descriptor_rva = import_rva
    for _ in range(section_end // 20):
        descriptor = rva_to_offset(descriptor_rva)
        assert descriptor + 20 <= section_end
        original_first_thunk = _read_test_elf_integer(artifact, descriptor, 4)
        library_name_rva = _read_test_elf_integer(artifact, descriptor + 12, 4)
        first_thunk = _read_test_elf_integer(artifact, descriptor + 16, 4)
        if original_first_thunk == 0 and library_name_rva == 0 and first_thunk == 0:
            break
        library_name = _read_test_pe_cstring(
            artifact, rva_to_offset(library_name_rva), section_end
        )
        assert library_name == b"KERNEL32.dll"
        thunk_rva = original_first_thunk or first_thunk
        assert thunk_rva != 0

        thunk_offset = rva_to_offset(thunk_rva)
        for _ in range(section_end // 8):
            assert thunk_offset + 8 <= section_end
            thunk = _read_test_elf_integer(artifact, thunk_offset, 8)
            thunk_offset += 8
            if thunk == 0:
                break
            assert thunk & (1 << 63) == 0, "ordinal-only import not representable"
            hint_name_offset = rva_to_offset(thunk & 0x7FFFFFFF)
            assert hint_name_offset + 2 < section_end
            name = _read_test_pe_cstring(artifact, hint_name_offset + 2, section_end)
            names.append(name.decode("ascii"))
        else:
            raise AssertionError("unterminated import thunk table")
        descriptor_rva += 20
    else:
        raise AssertionError("unterminated import descriptor table")

    return names


def test_rust_pe_api_import_producer_vectors_validate_independently() -> None:
    """Validate the shared Rust PE producer vector with the independent parser."""
    raw = _PE_API_IMPORT_PRODUCER_VECTOR_PATH.read_text(encoding="utf-8")
    producer_vectors = json.loads(raw, object_pairs_hook=_unique_object)

    assert set(producer_vectors.keys()) == {
        "vector_schema_version",
        "artifact_sha256",
        "artifact_hex",
        "cases",
    }
    assert producer_vectors["vector_schema_version"] == 1
    assert len(producer_vectors["cases"]) == 3

    artifact = bytes.fromhex(producer_vectors["artifact_hex"])
    assert artifact.hex() == producer_vectors["artifact_hex"]
    assert hashlib.sha256(artifact).hexdigest() == producer_vectors["artifact_sha256"]

    encountered = _extract_test_pe32_plus_imports(artifact)
    assert encountered == ["ReadFile", "CreateFileW", "VirtualAlloc", "ReadFile"]
    imports = sorted(set(encountered), key=lambda name: name.encode("ascii"))
    assert imports == ["CreateFileW", "ReadFile", "VirtualAlloc"]

    names = set()
    indexes = set()
    observable_values = set()
    for case in producer_vectors["cases"]:
        assert set(case.keys()) == {
            "name",
            "import_index",
            "api_import",
            "wire_hex",
        }
        assert case["name"] not in names
        names.add(case["name"])
        assert isinstance(case["import_index"], int)
        assert not isinstance(case["import_index"], bool)
        assert case["import_index"] not in indexes
        indexes.add(case["import_index"])
        assert case["api_import"] not in observable_values
        observable_values.add(case["api_import"])
        assert imports[case["import_index"]] == case["api_import"]

        wire = bytes.fromhex(case["wire_hex"])
        bundle = ObservableBundle.parse_canonical(wire)
        assert bundle.canonical_bytes == wire
        assert bundle.disclosure_policy == DisclosurePolicy.REVIEW_REQUIRED_V1
        assert bundle.scope.platform == ScopePlatform.WINDOWS
        assert bundle.scope.format == ScopeFormat.PE
        assert len(bundle.observables) == 1
        assert bundle.observables[0].kind == ObservableKind.API_IMPORT
        assert bundle.observables[0].value == case["api_import"]
    assert indexes == {0, 1, 2}
