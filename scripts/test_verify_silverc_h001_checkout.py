#!/usr/bin/env python3
"""Checkout/pin trust-boundary tests for scripts/verify_silverc_h001.py."""

from __future__ import annotations

import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import verify_silverc_h001 as vh  # noqa: E402

REAL_RUN = subprocess.run
ISOLATED_GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "test",
    "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "test",
    "GIT_COMMITTER_EMAIL": "test@example.invalid",
}


def git(repo: Path, *args: str) -> str:
    return REAL_RUN(
        ["git", *args], cwd=repo, check=True, text=True, capture_output=True
    ).stdout.strip()


class CheckoutPinTest(unittest.TestCase):
    def setUp(self) -> None:
        env_patch = mock.patch.dict(os.environ, ISOLATED_GIT_ENV)
        env_patch.start()
        self.addCleanup(env_patch.stop)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name).resolve()

        self.upstream = self.tmp / "upstream"
        (self.upstream / "silverscript-lang" / "tests").mkdir(parents=True)
        git(self.upstream, "init", "--quiet", "-b", "master")
        (self.upstream / "silverscript-lang" / "tests" / "common.rs").write_text(
            "// v1\n"
        )
        (self.upstream / ".gitignore").write_text("/target\n")
        git(self.upstream, "add", "-A")
        git(self.upstream, "commit", "--quiet", "-m", "v1")
        self.rev = git(self.upstream, "rev-parse", "HEAD")
        (self.upstream / "silverscript-lang" / "tests" / "common.rs").write_text(
            "// v2\n"
        )
        git(self.upstream, "commit", "--quiet", "-am", "v2")
        self.other_rev = git(self.upstream, "rev-parse", "HEAD")

        self.cargo_toml = self.tmp / "Cargo.toml"
        self.write_cargo_toml(
            f'{{ git = "{vh.SILVERSCRIPT_GIT}", rev = "{self.rev}" }}'
        )
        cargo_patch = mock.patch.object(vh, "WORKSPACE_CARGO_TOML", self.cargo_toml)
        cargo_patch.start()
        self.addCleanup(cargo_patch.stop)
        run_patch = mock.patch.object(vh.subprocess, "run", side_effect=self.fake_run)
        run_patch.start()
        self.addCleanup(run_patch.stop)
        self.checkout = self.tmp / "work" / "silverscript"

    def write_cargo_toml(
        self, entry: str, section: str = "workspace.dependencies"
    ) -> None:
        self.cargo_toml.write_text(
            f"[workspace]\nmembers = []\n\n[{section}]\nsilverscript-lang = {entry}\n",
            encoding="utf-8",
        )

    def fake_run(self, cmd: list[str], *args: Any, **kwargs: Any) -> Any:
        """Serve the canonical upstream URL from the local fixture repo (no network)."""
        cmd = list(cmd)
        if cmd[0] == "git" and "clone" in cmd:
            target = Path(cmd[-1])
            cmd = [
                str(self.upstream) if part == vh.SILVERSCRIPT_GIT else part
                for part in cmd
            ]
            proc = REAL_RUN(cmd, *args, **kwargs)
            if proc.returncode == 0:
                git(
                    Path(kwargs["cwd"]) / target,
                    "remote",
                    "set-url",
                    "origin",
                    vh.SILVERSCRIPT_GIT,
                )
            return proc
        if cmd[0] == "git" and "fetch" in cmd:
            cmd = [str(self.upstream) if part == "origin" else part for part in cmd]
        return REAL_RUN(cmd, *args, **kwargs)

    def assert_rejected(self, ref: str | None = None) -> vh.SilverscriptCheckoutError:
        with self.assertRaises(vh.SilverscriptCheckoutError) as ctx:
            vh.ensure_silverscript_repo(self.checkout, ref or self.rev)
        message = str(ctx.exception)
        self.assertNotIn(str(self.tmp), message)
        self.assertNotIn("/", message.replace("silverscript-lang", ""))
        return ctx.exception

    def fresh_checkout(self) -> None:
        vh.ensure_silverscript_repo(self.checkout, self.rev)
        self.assertEqual(git(self.checkout, "rev-parse", "HEAD"), self.rev)

    # --- workspace pin parsing ---------------------------------------------

    def test_real_workspace_pin_matches_active_default(self) -> None:
        real = Path(vh.__file__).resolve().parents[1] / "Cargo.toml"
        self.assertEqual(
            vh.workspace_silverscript_rev(real), vh.DEFAULT_SILVERSCRIPT_REF
        )
        vh.require_pinned_silverscript_ref(vh.DEFAULT_SILVERSCRIPT_REF, real)

    def test_workspace_pin_rejects_non_rev_or_non_canonical_entries(self) -> None:
        bad_entries = [
            f'{{ git = "{vh.SILVERSCRIPT_GIT}", tag = "v1" }}',
            f'{{ git = "{vh.SILVERSCRIPT_GIT}", rev = "{self.rev}", branch = "master" }}',
            f'{{ git = "https://github.com/evil/silverscript.git", rev = "{self.rev}" }}',
            f'{{ git = "{vh.SILVERSCRIPT_GIT}", rev = "{self.rev.upper()}" }}',
            f'{{ git = "{vh.SILVERSCRIPT_GIT}", rev = "{self.rev[:12]}" }}',
            '"0.1.0"',
        ]
        for entry in bad_entries:
            with self.subTest(entry=entry):
                self.write_cargo_toml(entry)
                with self.assertRaises(vh.SilverscriptCheckoutError):
                    vh.workspace_silverscript_rev()

    def test_workspace_pin_is_read_structurally_not_textually(self) -> None:
        self.write_cargo_toml(
            f'{{ git = "{vh.SILVERSCRIPT_GIT}", rev = "{self.rev}" }}',
            section="dependencies",
        )
        with self.assertRaises(vh.SilverscriptCheckoutError):
            vh.workspace_silverscript_rev()
        self.cargo_toml.write_text("[workspace\nnot toml", encoding="utf-8")
        with self.assertRaises(vh.SilverscriptCheckoutError) as ctx:
            vh.workspace_silverscript_rev()
        self.assertNotIn("not toml", str(ctx.exception))

    # --- requested ref ------------------------------------------------------

    def test_requested_ref_must_be_lowercase_hex40_and_equal_pin(self) -> None:
        for ref in (
            self.rev.upper(),
            self.rev[:7],
            f" {self.rev}",
            f"{self.rev}\n",
            "master",
            "HEAD",
            f"{self.rev}^{{commit}}",
            self.other_rev,
        ):
            with self.subTest(ref=ref):
                err = self.assert_rejected(ref)
                self.assertNotIn(ref.strip(), str(err))
        self.assertFalse(
            self.checkout.exists(), "rejected ref must not trigger a clone"
        )

    # --- fresh clone ----------------------------------------------------------

    def test_fresh_clone_checks_out_exact_pinned_head(self) -> None:
        self.fresh_checkout()
        self.assertEqual(git(self.checkout, "status", "--porcelain"), "")
        self.assertEqual(
            git(self.checkout, "config", "--get", "remote.origin.url"),
            vh.SILVERSCRIPT_GIT,
        )

    # --- existing checkout ----------------------------------------------------

    def test_existing_clean_canonical_checkout_is_accepted(self) -> None:
        self.fresh_checkout()
        git(self.checkout, "checkout", "--quiet", "--detach", self.other_rev)
        vh.ensure_silverscript_repo(self.checkout, self.rev)
        self.assertEqual(git(self.checkout, "rev-parse", "HEAD"), self.rev)

    def test_existing_checkout_rejects_symlink_path(self) -> None:
        self.fresh_checkout()
        linked_checkout = self.tmp / "linked-checkout"
        linked_checkout.symlink_to(self.checkout, target_is_directory=True)
        with self.assertRaises(vh.SilverscriptCheckoutError) as caught:
            vh.ensure_silverscript_repo(linked_checkout, self.rev)
        self.assertNotIn(str(self.tmp), str(caught.exception))

    def test_existing_checkout_requires_canonical_origin(self) -> None:
        self.fresh_checkout()
        git(
            self.checkout,
            "remote",
            "set-url",
            "origin",
            "https://github.com/evil/silverscript.git",
        )
        self.assert_rejected()

    def test_existing_checkout_rejects_multiple_origin_urls(self) -> None:
        self.fresh_checkout()
        git(
            self.checkout,
            "config",
            "--add",
            "remote.origin.url",
            "https://github.com/evil/x.git",
        )
        self.assert_rejected()

    def test_existing_checkout_rejects_insteadof_rewrite(self) -> None:
        self.fresh_checkout()
        git(
            self.checkout,
            "config",
            "url.https://github.com/evil/.insteadOf",
            "https://github.com/kaspanet/",
        )
        self.assert_rejected()

    def test_existing_checkout_without_origin_is_rejected(self) -> None:
        self.fresh_checkout()
        git(self.checkout, "remote", "remove", "origin")
        self.assert_rejected()

    def test_existing_checkout_rejects_tracked_modification(self) -> None:
        self.fresh_checkout()
        (self.checkout / "silverscript-lang" / "tests" / "common.rs").write_text(
            "// tampered\n"
        )
        self.assert_rejected()

    def test_existing_checkout_rejects_untracked_file(self) -> None:
        self.fresh_checkout()
        (
            self.checkout / "silverscript-lang" / "tests" / "prometheus_h001_probe.rs"
        ).write_text("x")
        self.assert_rejected()

    def test_existing_checkout_ignores_gitignored_build_output(self) -> None:
        self.fresh_checkout()
        (self.checkout / "target").mkdir()
        (self.checkout / "target" / "artifact").write_text("x")
        vh.ensure_silverscript_repo(self.checkout, self.rev)

    def test_existing_path_must_be_repository_root(self) -> None:
        self.fresh_checkout()
        self.checkout = self.checkout / "silverscript-lang"
        self.assert_rejected()

    def test_existing_non_repository_path_is_rejected(self) -> None:
        self.checkout.mkdir(parents=True)
        (self.checkout / "file").write_text("secret content")
        err = self.assert_rejected()
        self.assertNotIn("secret content", str(err))

    def test_existing_file_path_is_rejected(self) -> None:
        self.checkout.parent.mkdir(parents=True)
        self.checkout.write_text("x")
        self.assert_rejected()

    # --- post-checkout HEAD equality --------------------------------------------

    def test_head_mismatch_after_checkout_fails_closed(self) -> None:
        self.fresh_checkout()

        def lying_rev_parse(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
            if cmd[0] == "git" and "rev-parse" in cmd and "--verify" in cmd:
                return subprocess.CompletedProcess(
                    cmd, 0, stdout=f"{self.other_rev}\n", stderr=""
                )
            return self.fake_run(cmd, *args, **kwargs)

        with mock.patch.object(vh.subprocess, "run", side_effect=lying_rev_parse):
            err = self.assert_rejected()
        self.assertIn("HEAD", str(err))

    def test_full_hex_ref_wins_over_same_named_tag(self) -> None:
        self.fresh_checkout()
        git(self.checkout, "tag", self.rev, self.other_rev)
        with contextlib.redirect_stderr(io.StringIO()):
            vh.ensure_silverscript_repo(self.checkout, self.rev)
        self.assertEqual(git(self.checkout, "rev-parse", "HEAD"), self.rev)

    def test_unknown_commit_fails_closed(self) -> None:
        missing = "0" * 40
        self.write_cargo_toml(f'{{ git = "{vh.SILVERSCRIPT_GIT}", rev = "{missing}" }}')
        err = self.assert_rejected(missing)
        self.assertIn("git checkout", str(err))

    def test_repository_hooks_are_not_executed(self) -> None:
        self.fresh_checkout()
        marker = self.tmp / "hook-ran"
        hook = self.checkout / ".git" / "hooks" / "post-checkout"
        hook.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
        hook.chmod(0o755)
        vh.ensure_silverscript_repo(self.checkout, self.rev)
        self.assertFalse(marker.exists())

    # --- temporary probe ------------------------------------------------------

    def test_probe_removal_restores_clean_tree(self) -> None:
        self.fresh_checkout()
        probe = (
            self.checkout / "silverscript-lang" / "tests" / f"{vh.PROBE_TEST_NAME}.rs"
        )
        probe.write_text(vh.RUST_TEST)
        vh.remove_probe_and_require_clean_tree(self.checkout, probe)
        self.assertFalse(probe.exists())
        self.assertEqual(git(self.checkout, "status", "--porcelain"), "")
        vh.remove_probe_and_require_clean_tree(self.checkout, probe)

    def test_probe_removal_fails_closed_on_residual_changes(self) -> None:
        self.fresh_checkout()
        probe = (
            self.checkout / "silverscript-lang" / "tests" / f"{vh.PROBE_TEST_NAME}.rs"
        )
        probe.write_text(vh.RUST_TEST)
        (self.checkout / "silverscript-lang" / "tests" / "common.rs").write_text(
            "// changed\n"
        )
        with self.assertRaises(vh.SilverscriptCheckoutError):
            vh.remove_probe_and_require_clean_tree(self.checkout, probe)
        self.assertFalse(probe.exists())

    # --- main(): fail closed without leakage ------------------------------------

    def run_main(self, ref: str) -> tuple[int, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        env = {"SILVERSCRIPT_REPO": str(self.checkout), "SILVERSCRIPT_REF": ref}
        with (
            mock.patch.dict(os.environ, env),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            code = vh.main()
        return code, stdout.getvalue() + stderr.getvalue()

    def test_main_rejects_dirty_checkout_without_path_leak(self) -> None:
        self.fresh_checkout()
        (self.checkout / "silverscript-lang" / "tests" / "common.rs").write_text(
            "// secret-body\n"
        )
        code, output = self.run_main(self.rev)
        self.assertEqual(code, 1)
        self.assertIn("silverscript checkout rejected", output)
        self.assertNotIn(str(self.tmp), output)
        self.assertNotIn("secret-body", output)

    def test_main_rejects_unpinned_ref_before_any_git_call(self) -> None:
        code, output = self.run_main(self.other_rev)
        self.assertEqual(code, 1)
        self.assertNotIn(str(self.tmp), output)
        self.assertFalse(self.checkout.exists())

    def test_main_cleans_probe_after_cargo_and_fails_closed_on_residue(self) -> None:
        self.fresh_checkout()
        probe = (
            self.checkout / "silverscript-lang" / "tests" / f"{vh.PROBE_TEST_NAME}.rs"
        )

        def fake_cargo(
            cmd: list[str], cwd: Path, env: dict[str, str] | None = None
        ) -> None:
            self.assertTrue(probe.exists())
            (self.checkout / "stray").write_text("x")

        with mock.patch.object(vh, "run", side_effect=fake_cargo):
            code, output = self.run_main(self.rev)
        self.assertEqual(code, 1)
        self.assertFalse(probe.exists())
        self.assertNotIn(str(self.tmp), output)

    def test_main_succeeds_and_leaves_clean_tree(self) -> None:
        self.fresh_checkout()
        with mock.patch.object(vh, "run") as cargo:
            code, output = self.run_main(self.rev)
        self.assertEqual(code, 0)
        cargo.assert_called_once()
        self.assertEqual(
            git(self.checkout, "status", "--porcelain", "--untracked-files=all"), ""
        )
        self.assertNotIn(str(self.tmp), output)


if __name__ == "__main__":
    unittest.main()
