#!/usr/bin/env python3
"""Tests for the Guardian Python dependency reproducibility gate."""

from __future__ import annotations

import contextlib
import io
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import verify_guardian_python_deps as vgd  # noqa: E402

REPO = vgd.REPO_ROOT
HASH_A = "a" * 64
HASH_B = "b" * 64
HEADER = f"# Regenerate:\n#   {vgd.REGENERATE_COMMAND}\n"
DIRECT = "httpx==0.28.1\nyara-x==1.4.0\n"
LOCK = (
    HEADER
    + "httpcore==1.0.9 \\\n"
    + f"    --hash=sha256:{HASH_A}\n"
    + "    # via httpx\n"
    + "httpx==0.28.1 \\\n"
    + f"    --hash=sha256:{HASH_A} \\\n"
    + f"    --hash=sha256:{HASH_B}\n"
    + "    # via -r requirements.txt\n"
    + "typing-extensions==4.16.0 ; python_full_version < '3.15' \\\n"
    + f"    --hash=sha256:{HASH_B}\n"
    + "yara-x==1.4.0 \\\n"
    + f"    --hash=sha256:{HASH_A}\n"
)
YARA = 'PINNED_YARA_X_VERSION = "1.4.0"\n'


class GuardianDepsGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.write(direct=DIRECT, lock=LOCK, yara=YARA)

    def write(
        self,
        direct: str | None = None,
        lock: str | None = None,
        yara: str | None = None,
    ) -> None:
        for rel, text in (
            (vgd.REQUIREMENTS, direct),
            (vgd.LOCK, lock),
            (vgd.YARA_QUALITY, yara),
        ):
            if text is None:
                continue
            path = self.tmp / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")

    def errors(self) -> list[str]:
        errors, _ = vgd.verify(self.tmp)
        return errors

    def assert_fails(self, fragment: str) -> None:
        errors = self.errors()
        self.assertTrue(
            any(fragment in error for error in errors),
            f"{fragment!r} not in {errors}",
        )

    def test_fixture_passes(self) -> None:
        self.assertEqual(self.errors(), [])

    def test_real_repository_passes(self) -> None:
        errors, summary = vgd.verify(REPO)
        self.assertEqual(errors, [])
        self.assertIn("8 direct", summary)

    def test_real_ci_installs_lock_with_hashes_and_wheels_only(self) -> None:
        ci = (REPO / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn(
            "--require-hashes --only-binary :all: "
            "-r modules/guardian-node/requirements-lock.txt",
            ci,
        )
        self.assertNotIn("pip install -r modules/guardian-node/requirements.txt", ci)

    def test_floor_pin_rejected(self) -> None:
        self.write(direct="httpx>=0.25.0\nyara-x==1.4.0\n")
        self.assert_fails("not an exact name==version pin")

    def test_url_and_option_lines_rejected(self) -> None:
        for line in (
            "--index-url https://example.invalid/simple",
            "-e .",
            "httpx @ https://example.invalid/httpx.whl",
            "httpx==0.28.1 ; sys_platform == 'linux'",
        ):
            with self.subTest(line=line):
                self.write(direct=f"{line}\nyara-x==1.4.0\n")
                self.assert_fails("not an exact name==version pin")

    def test_duplicate_direct_pin_rejected(self) -> None:
        self.write(direct="httpx==0.28.1\nHTTPX==0.28.1\nyara-x==1.4.0\n")
        self.assert_fails("duplicate httpx")

    def test_empty_requirements_rejected(self) -> None:
        self.write(direct="# nothing\n")
        self.assert_fails("no pins")

    def test_direct_missing_from_lock_rejected(self) -> None:
        self.write(direct=DIRECT + "coincurve==21.0.0\n")
        self.assert_fails("direct dependency coincurve missing")

    def test_direct_version_drift_rejected(self) -> None:
        self.write(direct="httpx==0.28.2\nyara-x==1.4.0\n")
        self.assert_fails("httpx version differs")

    def test_lock_entry_without_hash_rejected(self) -> None:
        self.write(lock=LOCK + "pytest==9.1.1\n")
        self.assert_fails("unsupported line")
        self.write(lock=LOCK + "pytest==9.1.1 \\\n")
        self.assert_fails("truncated hash continuation")

    def test_malformed_hash_rejected(self) -> None:
        self.write(lock=LOCK.replace(f"sha256:{HASH_B}\n", "sha256:xyz\n", 1))
        self.assert_fails("expected hash line")

    def test_lock_index_and_url_lines_rejected(self) -> None:
        for line in (
            "--extra-index-url https://example.invalid/simple",
            "--find-links https://example.invalid/",
            "--trusted-host example.invalid",
            "evil @ https://example.invalid/evil.whl",
        ):
            with self.subTest(line=line):
                self.write(lock=LOCK + line + "\n")
                self.assert_fails("unsupported line")

    def test_duplicate_lock_entry_rejected(self) -> None:
        self.write(lock=LOCK + "httpx==0.28.1 \\\n" + f"    --hash=sha256:{HASH_A}\n")
        self.assert_fails("duplicate httpx")

    def test_missing_regenerate_header_rejected(self) -> None:
        self.write(lock=LOCK.replace(vgd.REGENERATE_COMMAND, "pip freeze"))
        self.assert_fails("regenerate command header missing")

    def test_yara_runtime_pin_drift_rejected(self) -> None:
        self.write(yara='PINNED_YARA_X_VERSION = "1.20.0"\n')
        self.assert_fails("differs from runtime pin")
        self.write(yara=YARA + YARA)
        self.assert_fails("not found exactly once")

    def test_missing_and_symlinked_files_rejected(self) -> None:
        (self.tmp / vgd.LOCK).unlink()
        self.assert_fails("requirements-lock.txt: file missing")
        target = self.tmp / "elsewhere.txt"
        target.write_text(LOCK, encoding="utf-8")
        (self.tmp / vgd.LOCK).symlink_to(target)
        self.assert_fails("requirements-lock.txt: symlink rejected")

    def test_oversized_file_rejected(self) -> None:
        self.write(direct=DIRECT + "#" * (vgd.MAX_FILE_BYTES + 1))
        self.assert_fails("file too large")

    def test_main_exit_codes_and_sorted_output(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(vgd.main(["--repo-root", str(self.tmp)]), 0)
        self.assertIn("OK (2 direct, 4 locked)", out.getvalue())
        self.write(direct="httpx>=1\nzz>=1\n")
        with contextlib.redirect_stderr(err):
            self.assertEqual(vgd.main(["--repo-root", str(self.tmp)]), 1)
        lines = [line for line in err.getvalue().splitlines() if line.startswith("- ")]
        self.assertEqual(lines, sorted(lines))


if __name__ == "__main__":
    unittest.main()
