#!/usr/bin/env python3
"""Tests for the public-page stylesheet regression gate."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import verify_site_css as vsc  # noqa: E402

ROOT = ":root{--void:#050505;--panel:#141414;--text:#E2E2E2;--dim:#8A8A8A}"


def page(css: str) -> str:
    return f"<html><head><style>{ROOT}{css}</style></head></html>"


class SiteCssGateTest(unittest.TestCase):
    def test_real_pages_pass(self) -> None:
        self.assertEqual(vsc.verify(vsc.REPO_ROOT), [])

    def test_clean_page_passes(self) -> None:
        self.assertEqual(
            vsc.check_page("p", page(".a{color:var(--dim)}.b{color:red}")), []
        )

    def test_pasted_over_duplicate_rejected(self) -> None:
        errors = vsc.check_page(
            "p",
            page(".f-links a{color:#4A5040}.x{margin:0}.f-links a{color:var(--dim)}"),
        )
        self.assertEqual(errors, ["p: '.f-links a' declares color 2 times"])

    def test_same_selector_different_properties_allowed(self) -> None:
        self.assertEqual(vsc.check_page("p", page(".a{color:red}.a{margin:0}")), [])

    def test_media_and_keyframes_are_not_top_level(self) -> None:
        css = ".a{color:red}@media(max-width:600px){.a{color:blue}}@keyframes k{from{opacity:0}to{opacity:1}}@keyframes j{from{opacity:0}to{opacity:1}}"
        self.assertEqual(vsc.check_page("p", page(css)), [])

    def test_low_contrast_token_rejected(self) -> None:
        html = "<style>:root{--void:#050505;--panel:#141414;--dim:#333333}</style>"
        errors = vsc.check_page("p", html)
        self.assertTrue(any("--dim on --void is 1.61:1" in e for e in errors), errors)
        self.assertTrue(any("--dim on --panel" in e for e in errors), errors)

    def test_contrast_math(self) -> None:
        self.assertAlmostEqual(vsc.contrast("#FFFFFF", "#000000"), 21.0, places=2)
        self.assertAlmostEqual(vsc.contrast("#666666", "#050505"), 3.55, places=2)

    def test_missing_stylesheet_rejected(self) -> None:
        self.assertEqual(
            vsc.check_page("p", "<html></html>"), ["p: embedded stylesheet missing"]
        )


if __name__ == "__main__":
    unittest.main()
