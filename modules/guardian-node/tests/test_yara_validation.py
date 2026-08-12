"""Adversarial tests for the GH-170 bounded YARA-X validation boundary."""

import pytest

from jaeger.yara_validation import (
    MAX_YARA_RULE_NAME_LENGTH,
    MAX_YARA_SOURCE_BYTES,
    validate_candidate_rule_source,
)


def _simple_rule(name: str, pattern: str = '$a = "x"') -> str:
    """Build a minimal compilable single-rule source with one string."""
    return (
        f"rule {name} {{\n"
        f"    strings:\n"
        f"        {pattern}\n"
        f"    condition:\n"
        f"        $a\n"
        f"}}"
    )


VALID_RULE = _simple_rule("TestRule", '$a = "malicious_payload"')
VALID_HEX_RULE = _simple_rule("HexRule", "$a = { 4D 5A 90 00 }")


def _oversized_valid_rule() -> str:
    padding = "A" * (MAX_YARA_SOURCE_BYTES - len(VALID_RULE) - len(" //") + 1)
    return f"{VALID_RULE} //{padding}"


class TestValidCandidates:
    """Well-formed single-rule sources must pass the boundary."""

    @pytest.mark.parametrize(
        "source",
        [
            VALID_RULE,
            VALID_HEX_RULE,
            (
                "rule Meta {\n"
                '    meta:\n        author = "prom"\n'
                '    strings:\n        $a = "x"\n'
                "    condition:\n        $a\n}"
            ),
            _simple_rule("Tagged : alpha beta"),
            "private " + _simple_rule("P"),
            "global " + _simple_rule("G"),
            "private global " + _simple_rule("PG"),
            "rule Stringless { condition: filesize > 0 }",
            _simple_rule("Re", "$a = /a.*b/"),
            _simple_rule("Quant", "$a = /ab{2,3}c/"),
            _simple_rule("Klass", "$a = /[a-z\\/]{4,}/"),
            _simple_rule("Jumps", "$a = { 4D 5A [0-4] 90 ?? }"),
            _simple_rule("N" * MAX_YARA_RULE_NAME_LENGTH),
        ],
        ids=[
            "plain",
            "hex",
            "meta",
            "tagged",
            "private",
            "global",
            "private-global",
            "stringless",
            "regex",
            "regex-quantifier",
            "regex-class-with-slash",
            "hex-jumps",
            "max-length-name",
        ],
    )
    def test_valid_rule_shapes_pass(self, source: str) -> None:
        assert validate_candidate_rule_source(source) is True

    @pytest.mark.parametrize(
        "source",
        [
            # The word "rule" inside a quoted string is not a declaration.
            _simple_rule("R", '$a = "rule Fake { condition: true }"'),
            # A rule-looking block comment is not a declaration.
            "/* rule Fake { condition: true } */\n" + VALID_RULE,
            # Directives inside comments are not directives.
            '// import "pe"\n// include "x.yar"\n' + VALID_RULE,
            # A regex that contains "rule B {" does not add a declaration.
            _simple_rule("A", "$a = /rule B \\{ condition: /"),
            # Escaped quotes do not end the quoted region early.
            _simple_rule("E", '$a = "he said \\"rule X\\""'),
            # A trailing line comment without newline terminates cleanly.
            VALID_RULE + " // trailing comment",
            # YARA-X and the scanner both keep CR/VT/FF inside line comments.
            '// import "pe"\r\x0b\x0c\n' + VALID_RULE,
        ],
        ids=[
            "rule-keyword-in-string",
            "rule-in-block-comment",
            "directives-in-line-comments",
            "rule-keyword-in-regex",
            "escaped-quotes",
            "unterminated-line-comment-at-eof",
            "control-characters-in-line-comment",
        ],
    )
    def test_lexer_regions_do_not_confuse_top_level_scan(self, source: str) -> None:
        assert validate_candidate_rule_source(source) is True


class TestInputBudgets:
    """Type, encoding, NUL, and size budgets fail closed."""

    @pytest.mark.parametrize(
        "source",
        [None, b"rule R { condition: true }", 42, 9.5, True, ["rule"], {"rule": 1}],
        ids=["none", "bytes", "int", "float", "bool", "list", "dict"],
    )
    def test_non_string_input_rejected(self, source: object) -> None:
        assert validate_candidate_rule_source(source) is False

    @pytest.mark.parametrize(
        "source",
        ["", "   \n\t  ", "\n\n"],
        ids=["empty", "whitespace", "newlines"],
    )
    def test_empty_or_ruleless_source_rejected(self, source: str) -> None:
        assert validate_candidate_rule_source(source) is False

    def test_nul_byte_rejected(self) -> None:
        assert validate_candidate_rule_source(VALID_RULE + "\x00") is False

    @pytest.mark.parametrize(
        "source",
        [
            _simple_rule("R", '$a = "caf\u00e9"'),
            VALID_RULE + " \U0001f600",
            "\ufeff" + VALID_RULE,
        ],
        ids=["non-ascii-string-literal", "emoji", "bom"],
    )
    def test_non_ascii_rejected(self, source: str) -> None:
        assert validate_candidate_rule_source(source) is False

    def test_oversized_source_rejected(self) -> None:
        oversized = _oversized_valid_rule()
        assert len(oversized) > MAX_YARA_SOURCE_BYTES
        assert validate_candidate_rule_source(oversized) is False

    def test_source_at_size_budget_accepted(self) -> None:
        padding = "A" * (MAX_YARA_SOURCE_BYTES - len(VALID_RULE) - len(" //"))
        source = f"{VALID_RULE} //{padding}"
        assert len(source) == MAX_YARA_SOURCE_BYTES
        assert validate_candidate_rule_source(source) is True

    def test_overlong_rule_name_rejected(self) -> None:
        source = _simple_rule("N" * (MAX_YARA_RULE_NAME_LENGTH + 1))
        assert validate_candidate_rule_source(source) is False


class TestRuleCountAndDirectives:
    """Exactly one top-level rule and no import/include directives."""

    def test_two_rules_rejected(self) -> None:
        source = _simple_rule("A") + "\n" + _simple_rule("B")
        assert validate_candidate_rule_source(source) is False

    def test_duplicate_rule_names_rejected(self) -> None:
        source = VALID_RULE + "\n" + VALID_RULE
        assert validate_candidate_rule_source(source) is False

    def test_no_rule_rejected(self) -> None:
        assert validate_candidate_rule_source("this is not valid yara") is False

    @pytest.mark.parametrize(
        "source",
        [
            'import "pe"\n' + VALID_RULE,
            'include "other.yar"\n' + VALID_RULE,
            VALID_RULE + '\nimport "pe"',
            VALID_RULE + '\ninclude "other.yar"',
            'import "pe"\nimport "elf"\n' + VALID_RULE,
        ],
        ids=[
            "import-before",
            "include-before",
            "import-after",
            "include-after",
            "double-import",
        ],
    )
    def test_top_level_directives_rejected(self, source: str) -> None:
        assert validate_candidate_rule_source(source) is False


class TestCompilerAuthority:
    """Syntax errors and compiler warnings fail closed."""

    @pytest.mark.parametrize(
        "source",
        [
            # Missing condition section is a syntax error.
            'rule Broken {\n    strings:\n        $a = "x"\n}',
            # Unused string is a compile error.
            _simple_rule("Unused") + "\nunused: true",
            # Malformed metadata is a syntax error.
            "rule M {\n    meta:\n        x = \n    condition:\n        true\n}",
            # Invalid identifier in the rule name is a syntax error.
            _simple_rule("bad-name"),
            # Unterminated quoted string.
            'rule U {\n    strings:\n        $a = "x\n    condition:\n        $a\n}',
            # Unterminated block comment.
            "/* never ends\n" + VALID_RULE,
            # Unbalanced body.
            VALID_RULE[: -len("}")],
        ],
        ids=[
            "missing-condition",
            "trailing-garbage",
            "malformed-meta",
            "invalid-rule-name",
            "unterminated-string",
            "unterminated-block-comment",
            "unbalanced-body",
        ],
    )
    def test_uncompilable_sources_rejected(self, source: str) -> None:
        assert validate_candidate_rule_source(source) is False

    @pytest.mark.parametrize(
        "source",
        [
            # Invariant boolean condition raises a compiler warning.
            "rule Broken {\n    condition:\n        true\n}",
            # An unused string with an invariant condition fails twice over.
            "rule Unused {\n"
            '    strings:\n        $a = "x"\n'
            "    condition:\n        true\n}",
            # Slow consecutive jumps raise compiler warnings.
            _simple_rule("Slow", "$a = { 01 [0-] 02 [0-] 03 [0-] 04 }"),
            # A hex pattern that is plain text raises a compiler warning.
            _simple_rule("TextHex", "$a = { 72 75 6C 65 }"),
        ],
        ids=[
            "invariant-condition-warning",
            "unused-string",
            "slow-pattern-warning",
            "text-as-hex-warning",
        ],
    )
    def test_warning_producing_sources_rejected(self, source: str) -> None:
        assert validate_candidate_rule_source(source) is False
