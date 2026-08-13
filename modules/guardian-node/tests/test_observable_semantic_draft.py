"""Adversarial tests for the GH-173 semantic-draft derivation boundary."""

# Exact-type assertions (int vs bool) and self-documenting test names are
# intentional throughout this file.
# pylint: disable=missing-function-docstring,unidiomatic-typecheck

from __future__ import annotations

import copy
import hashlib
import inspect
import json
import pickle

import pytest

import jaeger.observable_semantic_draft as draft_module
from jaeger.observable_semantic_draft import (
    ObservableSemanticDraft,
    ObservableSemanticDraftError,
    derive_semantic_draft,
)
from jaeger.threat_observable import Observable, ObservableBundle, ObservableKind
from jaeger.yara_validation import (
    MAX_YARA_SOURCE_BYTES,
    validate_candidate_rule_source,
)

_STABLE_MESSAGE = "observable semantic draft derivation failed"

_FILE_SHA256_A = "a" * 64
_FILE_SHA256_B = "b" * 64
_API_IMPORT_A = "CreateFileW"
_API_IMPORT_B = "kernel32.VirtualAlloc"
_BYTE_PATTERN_A = "4d 5a 90 00 03 00 00 00"
_BYTE_PATTERN_B = "b8 01 00 00 00 bb 02 00 ?? 00 00 cd 80"


def _make_bundle(observables, policy="review_required_v1") -> ObservableBundle:
    """Build one canonical bundle wire and parse it through the real parser."""
    payload = {
        "schema_version": 1,
        "disclosure_policy": policy,
        "scope": {"platform": "windows", "format": "pe"},
        "observables": [{"kind": kind, "value": value} for kind, value in observables],
    }
    wire = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    return ObservableBundle.parse_canonical(wire)


def _mixed_bundle() -> ObservableBundle:
    """Bundle with two api_import, one byte_pattern, one file_sha256."""
    return _make_bundle(
        [
            ("api_import", _API_IMPORT_A),
            ("api_import", _API_IMPORT_B),
            ("byte_pattern", _BYTE_PATTERN_A),
            ("file_sha256", _FILE_SHA256_A),
        ]
    )


def _forged_observable(kind, value) -> Observable:
    """Bypass the parser to build an invariant-violating observable."""
    observable = object.__new__(Observable)
    object.__setattr__(observable, "kind", kind)
    object.__setattr__(observable, "value", value)
    return observable


def _forged_bundle(observables) -> ObservableBundle:
    """Bypass the parser to build an exact-type bundle with raw observables."""
    bundle = object.__new__(ObservableBundle)
    object.__setattr__(bundle, "observables", observables)
    return bundle


class TestDerivation:
    """Well-formed bundles derive exact counts, digest, and verdict."""

    def test_mixed_kinds_exact_counts_digest_compile(self) -> None:
        result = derive_semantic_draft(_mixed_bundle())
        assert result.file_sha256_count == 1
        assert result.api_import_count == 2
        assert result.byte_pattern_count == 1
        assert type(result.file_sha256_count) is int
        assert type(result.api_import_count) is int
        assert type(result.byte_pattern_count) is int
        assert type(result.candidate_rule_sha256) is bytes
        assert len(result.candidate_rule_sha256) == 32
        assert any(result.candidate_rule_sha256)
        assert result.rule_compile_ok is True
        assert type(result.rule_compile_ok) is bool

    def test_same_bundle_byte_identical_output(self) -> None:
        bundle = _mixed_bundle()
        first = derive_semantic_draft(bundle)
        second = derive_semantic_draft(bundle)
        reparsed = derive_semantic_draft(_mixed_bundle())
        for other in (second, reparsed):
            assert other.file_sha256_count == first.file_sha256_count
            assert other.api_import_count == first.api_import_count
            assert other.byte_pattern_count == first.byte_pattern_count
            assert other.candidate_rule_sha256 == first.candidate_rule_sha256
            assert other.rule_compile_ok == first.rule_compile_ok

    def test_different_bundles_different_digests(self) -> None:
        baseline = derive_semantic_draft(_mixed_bundle())
        changed = derive_semantic_draft(
            _make_bundle(
                [
                    ("api_import", _API_IMPORT_A),
                    ("api_import", _API_IMPORT_B),
                    ("byte_pattern", _BYTE_PATTERN_B),
                    ("file_sha256", _FILE_SHA256_A),
                ]
            )
        )
        assert baseline.candidate_rule_sha256 != changed.candidate_rule_sha256

    def test_file_hash_only_compiles_with_false_condition(self) -> None:
        bundle = _make_bundle(
            [
                ("file_sha256", _FILE_SHA256_A),
                ("file_sha256", _FILE_SHA256_B),
            ],
            policy="public_auto_v1",
        )
        captured = []
        real_validator = validate_candidate_rule_source

        def spy(source):
            captured.append(source)
            return real_validator(source)

        bundle_result = None
        original = draft_module.validate_candidate_rule_source
        draft_module.validate_candidate_rule_source = spy
        try:
            bundle_result = derive_semantic_draft(bundle)
        finally:
            draft_module.validate_candidate_rule_source = original

        assert len(captured) == 1
        source = captured[0]
        assert "strings:" not in source
        assert "condition:" in source
        assert "any of them" not in source
        assert _FILE_SHA256_A not in source
        assert _FILE_SHA256_B not in source
        assert "hash" not in source
        assert "import" not in source.split("{")[0]
        assert bundle_result.rule_compile_ok is True
        assert bundle_result.file_sha256_count == 2
        assert bundle_result.api_import_count == 0
        assert bundle_result.byte_pattern_count == 0
        assert (
            bundle_result.candidate_rule_sha256
            == hashlib.sha256(source.encode("ascii")).digest()
        )

    def test_max_observables_boundary_compiles(self) -> None:
        observables = [("api_import", f"Import{i:02d}Function") for i in range(15)]
        observables.append(("file_sha256", _FILE_SHA256_A))
        result = derive_semantic_draft(_make_bundle(observables))
        assert result.api_import_count == 15
        assert result.file_sha256_count == 1
        assert result.byte_pattern_count == 0
        assert result.rule_compile_ok is True


class TestConstructionAndSerialization:
    """The result type is non-constructible and non-serializable."""

    def test_direct_construction_rejected(self) -> None:
        with pytest.raises(TypeError):
            ObservableSemanticDraft()

    def test_pickle_rejected(self) -> None:
        result = derive_semantic_draft(_mixed_bundle())
        with pytest.raises(TypeError):
            pickle.dumps(result)

    def test_copy_rejected(self) -> None:
        result = derive_semantic_draft(_mixed_bundle())
        with pytest.raises(TypeError):
            copy.copy(result)
        with pytest.raises(TypeError):
            copy.deepcopy(result)

    def test_result_exposes_no_source(self) -> None:
        result = derive_semantic_draft(_mixed_bundle())
        assert set(vars(result).keys()) == {
            "file_sha256_count",
            "api_import_count",
            "byte_pattern_count",
            "candidate_rule_sha256",
            "rule_compile_ok",
        }
        assert not hasattr(result, "source")
        assert not hasattr(result, "rule_source")
        assert not hasattr(result, "candidate_source")
        rendered = repr(result)
        assert _API_IMPORT_A not in rendered
        assert _BYTE_PATTERN_A not in rendered
        assert _FILE_SHA256_A not in rendered

    def test_result_is_immutable(self) -> None:
        result = derive_semantic_draft(_mixed_bundle())
        with pytest.raises(Exception):
            result.rule_compile_ok = False  # type: ignore[misc]


class TestInvalidInput:
    """Invalid input fails closed with one stable redacted error."""

    @pytest.mark.parametrize(
        "bad_input",
        [
            None,
            True,
            42,
            "bundle",
            b"bundle",
            [],
            {},
            object(),
        ],
        ids=[
            "none",
            "bool",
            "int",
            "str",
            "bytes",
            "list",
            "dict",
            "object",
        ],
    )
    def test_wrong_input_types_rejected(self, bad_input) -> None:
        with pytest.raises(ObservableSemanticDraftError) as excinfo:
            derive_semantic_draft(bad_input)
        assert str(excinfo.value) == _STABLE_MESSAGE

    def test_observable_is_not_a_bundle(self) -> None:
        bundle = _mixed_bundle()
        with pytest.raises(ObservableSemanticDraftError) as excinfo:
            derive_semantic_draft(bundle.observables[0])
        assert str(excinfo.value) == _STABLE_MESSAGE

    def test_subclass_instance_rejected(self) -> None:
        class _SubclassedBundle(ObservableBundle):
            """Subclass must not satisfy the exact-type boundary."""

        forged = object.__new__(_SubclassedBundle)
        with pytest.raises(ObservableSemanticDraftError) as excinfo:
            derive_semantic_draft(forged)
        assert str(excinfo.value) == _STABLE_MESSAGE

    def test_forged_bundle_without_state_rejected(self) -> None:
        forged = object.__new__(ObservableBundle)
        with pytest.raises(ObservableSemanticDraftError) as excinfo:
            derive_semantic_draft(forged)
        assert str(excinfo.value) == _STABLE_MESSAGE

    def test_forged_bundle_with_only_valid_observables_rejected(self) -> None:
        forged = _forged_bundle(
            (_forged_observable(ObservableKind.FILE_SHA256, _FILE_SHA256_A),)
        )
        with pytest.raises(ObservableSemanticDraftError) as excinfo:
            derive_semantic_draft(forged)
        assert str(excinfo.value) == _STABLE_MESSAGE

    def test_forged_bundle_empty_observables_rejected(self) -> None:
        with pytest.raises(ObservableSemanticDraftError):
            derive_semantic_draft(_forged_bundle(()))

    def test_forged_bundle_non_tuple_observables_rejected(self) -> None:
        with pytest.raises(ObservableSemanticDraftError):
            derive_semantic_draft(_forged_bundle(["not", "a", "tuple"]))

    def test_forged_observable_wrong_type_rejected(self) -> None:
        with pytest.raises(ObservableSemanticDraftError):
            derive_semantic_draft(_forged_bundle(("not-an-observable",)))

    @pytest.mark.parametrize(
        ("kind", "value"),
        [
            (ObservableKind.API_IMPORT, 'evil"import"'),
            (ObservableKind.API_IMPORT, "back\\slash"),
            (ObservableKind.API_IMPORT, "1StartsWithDigit"),
            (ObservableKind.API_IMPORT, "x" * 97),
            (ObservableKind.API_IMPORT, ""),
            (ObservableKind.BYTE_PATTERN, "zz " * 8),
            (ObservableKind.BYTE_PATTERN, "4d 5a"),
            (ObservableKind.BYTE_PATTERN, "?? ?? ?? ?? ?? ?? ?? ??"),
            (ObservableKind.BYTE_PATTERN, "4d 5a } 90 00 03 00 00"),
            (ObservableKind.FILE_SHA256, "a" * 63),
            (ObservableKind.FILE_SHA256, "A" * 64),
            (ObservableKind.FILE_SHA256, "g" * 64),
        ],
        ids=[
            "api-quote-injection",
            "api-backslash-injection",
            "api-digit-start",
            "api-too-long",
            "api-empty",
            "byte-non-hex",
            "byte-too-few-tokens",
            "byte-all-wildcards",
            "byte-brace-injection",
            "sha-too-short",
            "sha-uppercase",
            "sha-non-hex",
        ],
    )
    def test_invariant_violating_values_rejected(self, kind, value) -> None:
        forged = _forged_bundle((_forged_observable(kind, value),))
        with pytest.raises(ObservableSemanticDraftError) as excinfo:
            derive_semantic_draft(forged)
        assert str(excinfo.value) == _STABLE_MESSAGE
        if value:
            assert value not in str(excinfo.value)

    def test_forged_observable_bad_field_types_rejected(self) -> None:
        forged = _forged_bundle((_forged_observable("api_import", _API_IMPORT_A),))
        with pytest.raises(ObservableSemanticDraftError):
            derive_semantic_draft(forged)
        forged = _forged_bundle(
            (_forged_observable(ObservableKind.API_IMPORT, b"bytes-value"),)
        )
        with pytest.raises(ObservableSemanticDraftError):
            derive_semantic_draft(forged)


class TestValidatorFailureModes:
    """Validator outcomes fail closed in exactly one way each."""

    def test_validator_false_records_false_verdict(self, monkeypatch) -> None:
        monkeypatch.setattr(
            draft_module, "validate_candidate_rule_source", lambda source: False
        )
        result = derive_semantic_draft(_mixed_bundle())
        assert result.rule_compile_ok is False
        assert type(result.rule_compile_ok) is bool
        assert len(result.candidate_rule_sha256) == 32
        assert any(result.candidate_rule_sha256)

    def test_validator_exception_becomes_stable_error(self, monkeypatch) -> None:
        def explode(source):
            raise RuntimeError("sensitive upstream detail")

        monkeypatch.setattr(draft_module, "validate_candidate_rule_source", explode)
        with pytest.raises(ObservableSemanticDraftError) as excinfo:
            derive_semantic_draft(_mixed_bundle())
        assert str(excinfo.value) == _STABLE_MESSAGE
        assert "sensitive upstream detail" not in str(excinfo.value)
        assert excinfo.value.__cause__ is None

    @pytest.mark.parametrize(
        "verdict",
        [None, 1, "true", b"\x01"],
        ids=["none", "int", "str", "bytes"],
    )
    def test_non_bool_verdict_fails_closed(self, monkeypatch, verdict) -> None:
        monkeypatch.setattr(
            draft_module, "validate_candidate_rule_source", lambda source: verdict
        )
        with pytest.raises(ObservableSemanticDraftError) as excinfo:
            derive_semantic_draft(_mixed_bundle())
        assert str(excinfo.value) == _STABLE_MESSAGE

    def test_budget_asserted_before_validator(self, monkeypatch) -> None:
        calls = []
        monkeypatch.setattr(
            draft_module,
            "validate_candidate_rule_source",
            lambda source: calls.append(source) or True,
        )
        monkeypatch.setattr(draft_module, "MAX_YARA_SOURCE_BYTES", 8)
        with pytest.raises(ObservableSemanticDraftError) as excinfo:
            derive_semantic_draft(_mixed_bundle())
        assert str(excinfo.value) == _STABLE_MESSAGE
        assert not calls

    def test_real_budget_never_exceeded(self, monkeypatch) -> None:
        captured = []
        real_validator = validate_candidate_rule_source

        def spy(source):
            captured.append(source)
            return real_validator(source)

        monkeypatch.setattr(draft_module, "validate_candidate_rule_source", spy)
        result = derive_semantic_draft(_mixed_bundle())
        assert result.rule_compile_ok is True
        assert len(captured) == 1
        assert len(captured[0].encode("ascii")) <= MAX_YARA_SOURCE_BYTES


class TestBoundaryDiscipline:
    """The boundary never scans data and never emits observable values."""

    def test_no_scan_api_in_module(self) -> None:
        source = inspect.getsource(draft_module)
        assert ".scan(" not in source
        assert "yara_x" not in source

    def test_candidate_source_contains_no_file_hashes(self, monkeypatch) -> None:
        captured = []
        real_validator = validate_candidate_rule_source

        def spy(source):
            captured.append(source)
            return real_validator(source)

        monkeypatch.setattr(draft_module, "validate_candidate_rule_source", spy)
        derive_semantic_draft(_mixed_bundle())
        assert len(captured) == 1
        source = captured[0]
        assert _FILE_SHA256_A not in source
        assert not source.startswith("import")
        assert "\nimport" not in source
        assert "include" not in source
        assert "any of them" in source
        assert "all of them" not in source
