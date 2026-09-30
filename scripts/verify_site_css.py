#!/usr/bin/env python3
"""Static regression gate for the public pages' embedded stylesheets (PRM-43).

Fails when a page stylesheet re-declares a property for an identical top-level
selector (the paste-over pattern that silently overrode readable colors), or
when a text color token does not reach WCAG AA (4.5:1) against every page
background token. Offline; reads only the listed HTML files.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PAGES = (
    "index.html",
    "roadmap.html",
    "faq.html",
    "whitepaper.html",
    "guardian-economics.html",
)
TEXT_TOKENS = ("--text", "--silver", "--silver-dim", "--muted", "--dim", "--mint")
BACKGROUND_TOKENS = ("--void", "--deep", "--surface", "--panel")
AA_NORMAL = 4.5
STYLE_RE = re.compile(r"<style>(.*?)</style>", re.S)
AT_BLOCK_RE = re.compile(r"\s*@[a-zA-Z-]+[^{;]*\{")
TOKEN_RE = re.compile(r"(--[a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{6})\b")


def luminance(hex_color: str) -> float:
    channels = [int(hex_color[i : i + 2], 16) / 255 for i in (1, 3, 5)]

    def linear(value: float) -> float:
        return value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4

    red, green, blue = (linear(c) for c in channels)
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def contrast(first: str, second: str) -> float:
    high, low = sorted((luminance(first), luminance(second)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def top_level_rules(css: str) -> list[tuple[str, str]]:
    """Return (selector, body) for top-level style rules; @-blocks are skipped."""
    rules: list[tuple[str, str]] = []
    index = 0
    while index < len(css):
        at_block = AT_BLOCK_RE.match(css, index)
        if at_block:
            depth = 0
            cursor = css.index("{", at_block.start())
            while cursor < len(css):
                if css[cursor] == "{":
                    depth += 1
                elif css[cursor] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                cursor += 1
            index = cursor + 1
            continue
        open_brace = css.find("{", index)
        if open_brace < 0:
            break
        close_brace = css.find("}", open_brace)
        if close_brace < 0:
            break
        selector = re.sub(r"/\*.*?\*/", "", css[index:open_brace], flags=re.S)
        rules.append((" ".join(selector.split()), css[open_brace + 1 : close_brace]))
        index = close_brace + 1
    return rules


def check_page(name: str, html: str) -> list[str]:
    errors: list[str] = []
    match = STYLE_RE.search(html)
    if match is None:
        return [f"{name}: embedded stylesheet missing"]
    css = match.group(1)
    declared: dict[tuple[str, str], int] = {}
    for selector, body in top_level_rules(css):
        for declaration in body.split(";"):
            if ":" not in declaration or not declaration.strip():
                continue
            prop = declaration.split(":", 1)[0].strip()
            if prop.startswith("--"):
                continue
            key = (selector, prop)
            declared[key] = declared.get(key, 0) + 1
    for (selector, prop), count in sorted(declared.items()):
        if count > 1:
            errors.append(f"{name}: '{selector}' declares {prop} {count} times")
    tokens: dict[str, str] = {}
    for token, value in TOKEN_RE.findall(css):
        tokens.setdefault(token, value)
    for text in TEXT_TOKENS:
        if text not in tokens:
            continue
        for background in BACKGROUND_TOKENS:
            if background not in tokens:
                continue
            ratio = contrast(tokens[text], tokens[background])
            if ratio < AA_NORMAL:
                errors.append(
                    f"{name}: {text} on {background} is {ratio:.2f}:1 (< {AA_NORMAL}:1)"
                )
    return errors


def verify(root: Path) -> list[str]:
    errors: list[str] = []
    for page in PAGES:
        path = root / page
        try:
            html = path.read_text(encoding="utf-8")
        except OSError:
            errors.append(f"{page}: unreadable")
            continue
        errors.extend(check_page(page, html))
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)
    errors = verify(args.repo_root)
    if errors:
        print("site css: FAIL", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"site css: OK ({len(PAGES)} pages)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
