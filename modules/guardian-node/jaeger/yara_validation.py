"""Bounded compile-only YARA-X validation for generated candidate rules.

GH-170 replaces the former substring-only candidate-rule check with one
pinned, real, compile-only YARA-X boundary (``yara-x==1.4.0``). Candidate
source stays in memory: it is never written to disk and never scanned
against any file, process, or data.

Validation fails closed. A candidate is accepted only when all of the
following hold:

* the input is a non-empty ASCII string with no NUL bytes and at most
  ``MAX_YARA_SOURCE_BYTES`` bytes;
* a bounded conservative source lexer finds exactly one top-level rule
  declaration with a bounded identifier name and no top-level ``import``
  or ``include`` directive;
* the pinned YARA-X compiler (includes disabled) accepts the source with
  zero errors and zero warnings and builds compiled rules.

The lexer only understands comments and quoted, regex, and hex regions
well enough to count top-level rule declarations and to spot import or
include directives; the compiler remains the syntax authority. This is a
structural safety boundary only. It establishes no semantic detection
quality, adversarial robustness, or production authority, and it performs
no model, network, file, process, wallet, or chain operation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

import yara_x

MAX_YARA_SOURCE_BYTES: Final[int] = 65_536
MAX_YARA_RULE_NAME_LENGTH: Final[int] = 128

_DIRECTIVE_TOKENS: Final[frozenset[str]] = frozenset({"import", "include"})
_RULE_TOKEN: Final[str] = "rule"
_IDENTIFIER_CHARS: Final[frozenset[str]] = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
)
_IDENTIFIER_START_CHARS: Final[frozenset[str]] = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"
)

# Lexer modes. NORMAL behavior depends on whether the scanner is at top
# level or inside the single rule body (tracked by ``depth``).
_NORMAL: Final[str] = "normal"
_LINE_COMMENT: Final[str] = "line_comment"
_BLOCK_COMMENT: Final[str] = "block_comment"
_QUOTED: Final[str] = "quoted"
_REGEX: Final[str] = "regex"
_HEX: Final[str] = "hex"


@dataclass
class _LexResult:
    """Conservative top-level scan summary for one candidate source."""

    rule_count: int = 0
    rule_name: str | None = None
    directive_found: bool = False
    terminated: bool = False


# Each rejected boundary condition returns immediately to keep fail-closed
# behavior explicit and independently reviewable.
# pylint: disable-next=too-many-return-statements
def validate_candidate_rule_source(source: object) -> bool:
    """Return True only if source passes the bounded compile-only boundary.

    Every malformed, oversized, non-ASCII, multi-rule, directive-bearing,
    warning-producing, or uncompilable input returns False.
    """
    if not isinstance(source, str) or not source:
        return False
    if not source.isascii() or "\x00" in source:
        return False
    # ASCII-only input has identical character and byte counts.
    if len(source) > MAX_YARA_SOURCE_BYTES:
        return False
    scan = _TopLevelScanner(source).scan()
    if not scan.terminated or scan.directive_found or scan.rule_count != 1:
        return False
    if scan.rule_name is None or len(scan.rule_name) > MAX_YARA_RULE_NAME_LENGTH:
        return False
    if any(char not in _IDENTIFIER_CHARS for char in scan.rule_name):
        return False
    return _compiles_clean(source)


class _TopLevelScanner:  # pylint: disable=too-few-public-methods
    """Conservative single-pass scanner for top-level YARA structure.

    The scanner tracks line and block comments, double-quoted strings,
    regex literals (including character classes), and hex strings so the
    words ``rule``, ``import``, and ``include`` inside those regions are
    never mistaken for top-level declarations. YARA has no ``/`` division
    operator, so a slash that does not open a comment opens a regex. Inside
    a rule body every ``{`` outside a comment, quoted string, or regex
    opens a hex string, so body depth never exceeds one.
    """

    def __init__(self, source: str) -> None:
        self._source = source
        self._index = 0
        self._mode = _NORMAL
        self._in_regex_class = False
        self._depth = 0
        self._expecting_rule_name = False
        self._result = _LexResult()

    def scan(self) -> _LexResult:
        """Scan the whole source and summarize top-level structure."""
        while self._index < len(self._source):
            if self._mode == _NORMAL:
                self._step_normal()
            else:
                self._step_region()
            self._index += 1
        # A line comment runs to end of source without a newline.
        self._result.terminated = (
            self._mode in (_NORMAL, _LINE_COMMENT) and self._depth == 0
        )
        return self._result

    def _step_region(self) -> None:
        char = self._source[self._index]
        if self._mode == _LINE_COMMENT:
            if char == "\n":
                self._mode = _NORMAL
        elif self._mode == _BLOCK_COMMENT:
            if char == "*" and self._following() == "/":
                self._mode = _NORMAL
                self._index += 1
        elif self._mode == _QUOTED:
            if char == "\\":
                self._index += 1
            elif char == '"':
                self._mode = _NORMAL
        elif self._mode == _REGEX:
            self._step_regex(char)
        elif char == "}":
            self._mode = _NORMAL

    def _step_regex(self, char: str) -> None:
        if char == "\\":
            self._index += 1
        elif char == "[":
            self._in_regex_class = True
        elif char == "]":
            self._in_regex_class = False
        elif char == "/" and not self._in_regex_class:
            self._mode = _NORMAL

    def _step_normal(self) -> None:
        char = self._source[self._index]
        following = self._following()
        if char == "/" and following == "/":
            self._mode = _LINE_COMMENT
            self._index += 1
        elif char == "/" and following == "*":
            self._mode = _BLOCK_COMMENT
            self._index += 1
        elif char == '"':
            self._mode = _QUOTED
        elif char == "/":
            self._mode = _REGEX
            self._in_regex_class = False
        elif self._depth == 0 and char == "{":
            self._depth = 1
        elif self._depth == 1 and char == "{":
            self._mode = _HEX
        elif self._depth == 1 and char == "}":
            self._depth = 0
        elif char in _IDENTIFIER_START_CHARS:
            self._read_identifier()

    def _read_identifier(self) -> None:
        end = self._index + 1
        while end < len(self._source) and self._source[end] in _IDENTIFIER_CHARS:
            end += 1
        token = self._source[self._index : end]
        self._index = end - 1
        if self._depth != 0:
            return
        if token in _DIRECTIVE_TOKENS:
            self._result.directive_found = True
        elif token == _RULE_TOKEN:
            self._result.rule_count += 1
            self._expecting_rule_name = True
        elif self._expecting_rule_name:
            self._result.rule_name = token
            self._expecting_rule_name = False

    def _following(self) -> str:
        if self._index + 1 < len(self._source):
            return self._source[self._index + 1]
        return ""


def _compiles_clean(source: str) -> bool:
    """Return True only if pinned YARA-X compiles source with no findings.

    Includes are disabled and any compiler warning fails closed. Any
    unexpected compiler failure also fails closed.
    """
    try:
        # pylint: disable-next=no-member
        compiler = yara_x.Compiler()
        compiler.enable_includes(False)
        compiler.add_source(source)
        if compiler.errors() or compiler.warnings():
            return False
        compiler.build()
    except Exception:  # noqa: BLE001  # pylint: disable=broad-except
        return False
    return True
