#!/usr/bin/env python3
"""Tests for the Rusty Kaspa / SilverScript toolchain pin gate."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import verify_toolchain_pins as vtp  # noqa: E402

REPO = vtp.REPO_ROOT
POLICY_PATH = REPO / vtp.DEFAULT_POLICY
POLICY = vtp.parse_policy(POLICY_PATH.read_text(encoding="utf-8"))
KASPA_URL = POLICY.kaspa_url
KASPA_SOURCE = POLICY.kaspa_source
SS_SOURCE = POLICY.silverscript_source
OTHER_COMMIT = "0" * 40
FORK_URL = "https://github.com/example/rusty-kaspa.git"
FORBIDDEN_CLAIM_TERMS = (
    "approv",
    "rollout",
    "roll-out",
    "candidate",
    "promot",
    "mainnet",
    "production-ready",
    "release-ready",
)
EMITTED: list[str] = []


def run_main(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = vtp.main(argv)
    EMITTED.append(out.getvalue() + err.getvalue())
    return code, out.getvalue(), err.getvalue()


class Fixture(unittest.TestCase):
    """Copies the pin-relevant files of the real checkout into a temp tree."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        manifest = tomllib.loads((REPO / "Cargo.toml").read_text(encoding="utf-8"))
        members: list[str] = manifest["workspace"]["members"]
        rel_paths = [
            Path("Cargo.toml"),
            Path("Cargo.lock"),
            vtp.THREAT_PROOF_LIB,
            vtp.RELATION_MANIFEST_PY,
            vtp.DEFAULT_POLICY,
            *(Path(m) / "Cargo.toml" for m in members),
        ]
        for rel in rel_paths:
            dest = self.root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / rel, dest)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def edit(self, rel: str | Path, old: str, new: str, count: int = 1) -> None:
        path = self.root / rel
        text = path.read_text(encoding="utf-8")
        self.assertGreaterEqual(text.count(old), count, f"{old!r} not in {rel}")
        path.write_text(text.replace(old, new, count), encoding="utf-8")

    def edit_all(self, rel: str | Path, old: str, new: str) -> None:
        path = self.root / rel
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text)
        path.write_text(text.replace(old, new), encoding="utf-8")

    def append(self, rel: str | Path, extra: str) -> None:
        path = self.root / rel
        path.write_text(path.read_text(encoding="utf-8") + extra, encoding="utf-8")

    def write_policy(self, data: Any) -> None:
        (self.root / vtp.DEFAULT_POLICY).write_text(json.dumps(data), encoding="utf-8")

    def policy_data(self) -> dict[str, Any]:
        data: dict[str, Any] = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        return data

    def errors(self) -> list[str]:
        code, out, err = run_main(["--repo-root", str(self.root)])
        self.assertEqual(out, "")
        self.assertEqual(code, 1, err)
        lines = err.splitlines()
        self.assertEqual(lines[0], "toolchain pins: FAIL")
        return [line.removeprefix("- ") for line in lines[1:]]

    def assert_error(self, *fragments: str) -> list[str]:
        errors = self.errors()
        self.assertTrue(
            any(all(f in e for f in fragments) for e in errors),
            f"no error containing {fragments}: {errors}",
        )
        return errors


class RealRepoTest(unittest.TestCase):
    def test_real_repo_passes(self) -> None:
        code, out, err = run_main([])
        self.assertEqual((code, err), (0, ""))
        self.assertTrue(out.startswith("toolchain pins: OK rusty-kaspa "))

    def test_real_policy_shape(self) -> None:
        self.assertEqual(len(POLICY.kaspa_direct), 8)
        self.assertEqual(POLICY.silverscript_package, "silverscript-lang")
        text = POLICY_PATH.read_text(encoding="utf-8").lower()
        for term in FORBIDDEN_CLAIM_TERMS:
            self.assertNotIn(term, text)

    def test_fixture_copy_passes_and_is_deterministic(self) -> None:
        fx = Fixture()
        fx.setUp()
        try:
            first = run_main(["--repo-root", str(fx.root)])
            second = run_main(["--repo-root", str(fx.root)])
            self.assertEqual(first[0], 0, first[2])
            self.assertEqual(first, second)
        finally:
            fx.tearDown()


class CargoTomlDriftTest(Fixture):
    def test_direct_tag_drift(self) -> None:
        self.edit(
            "Cargo.toml",
            f'kaspa-hashes = {{ git = "{KASPA_URL}", tag = "v2.0.1" }}',
            f'kaspa-hashes = {{ git = "{KASPA_URL}", tag = "v2.0.2" }}',
        )
        self.assert_error("workspace dependency kaspa-hashes", "tag 'v2.0.2'")

    def test_direct_url_drift(self) -> None:
        self.edit(
            "Cargo.toml",
            f'kaspa-bip32 = {{ git = "{KASPA_URL}"',
            f'kaspa-bip32 = {{ git = "{FORK_URL}"',
        )
        self.assert_error("workspace dependency kaspa-bip32", "git URL")

    def test_direct_rev_instead_of_tag(self) -> None:
        self.edit(
            "Cargo.toml",
            f'kaspa-addresses = {{ git = "{KASPA_URL}", tag = "v2.0.1" }}',
            f'kaspa-addresses = {{ git = "{KASPA_URL}", rev = "{POLICY.kaspa_commit}" }}',
        )
        errors = self.assert_error("kaspa-addresses", "unexpected keys ['rev']")
        self.assertTrue(any("kaspa-addresses: tag None" in e for e in errors))

    def test_missing_direct_dependency(self) -> None:
        self.edit(
            "Cargo.toml", "kaspa-txscript-errors = {", "not-kaspa-txscript-errors = {"
        )
        self.assert_error("kaspa-txscript-errors", "missing or not a git table")

    def test_unlisted_workspace_kaspa_dependency(self) -> None:
        self.edit(
            "Cargo.toml",
            "# Common dependencies\n",
            f'kaspa-core = {{ git = "{KASPA_URL}", tag = "v2.0.1" }}\n# Common dependencies\n',
        )
        self.assert_error("kaspa-core", "Rusty Kaspa crate not in policy")

    def test_renamed_rusty_kaspa_dependency(self) -> None:
        self.edit(
            "Cargo.toml",
            "# Common dependencies\n",
            f'kcore = {{ git = "{FORK_URL}", tag = "v2.0.1", package = "kaspa-core" }}\n'
            "# Common dependencies\n",
        )
        self.assert_error("workspace dependency kcore", "not in policy")

    def test_member_bypasses_workspace_pin(self) -> None:
        self.edit(
            "modules/client/Cargo.toml",
            "kaspa-hashes.workspace = true",
            f'kaspa-hashes = {{ git = "{FORK_URL}", tag = "v2.0.1" }}',
        )
        self.assert_error(
            "modules/client/Cargo.toml [dependencies] kaspa-hashes", "inherit"
        )

    def test_member_target_dependency_bypass(self) -> None:
        self.append(
            "modules/threat-hint/Cargo.toml",
            f'\n[target.\'cfg(unix)\'.dev-dependencies]\nkaspa-math = {{ git = "{KASPA_URL}", tag = "v2.0.1" }}\n',
        )
        self.assert_error("[target.cfg(unix).dev-dependencies] kaspa-math", "inherit")

    def test_patch_override_rejected(self) -> None:
        self.append(
            "Cargo.toml",
            f'\n[patch."{KASPA_URL}"]\nkaspa-core = {{ path = "../kc" }}\n',
        )
        self.assert_error("[patch.", "overrides a pinned source")

    def test_invalid_manifest_toml(self) -> None:
        self.append("Cargo.toml", "\n[workspace\n")
        self.assert_error("Cargo.toml: invalid TOML")


class CargoLockDriftTest(Fixture):
    def test_locked_commit_drift_splits_graph(self) -> None:
        self.edit(
            "Cargo.lock",
            KASPA_SOURCE,
            KASPA_SOURCE.replace(POLICY.kaspa_commit, OTHER_COMMIT),
        )
        errors = self.assert_error("Cargo.lock kaspa-", f"commit '{OTHER_COMMIT}'")
        self.assertTrue(
            any("split Kaspa source graph across 2 sources" in e for e in errors)
        )

    def test_locked_tag_drift_everywhere(self) -> None:
        self.edit_all(
            "Cargo.lock", "rusty-kaspa.git?tag=v2.0.1#", "rusty-kaspa.git?tag=v2.0.2#"
        )
        errors = self.assert_error("Cargo.lock kaspa-core", "is not the policy tag")
        self.assertFalse(any("split" in e for e in errors))

    def test_locked_source_url_drift(self) -> None:
        self.edit("Cargo.lock", KASPA_SOURCE, KASPA_SOURCE.replace(KASPA_URL, FORK_URL))
        self.assert_error("Cargo.lock kaspa-", f"source URL '{FORK_URL}'")

    def test_locked_registry_resolution(self) -> None:
        self.edit(
            "Cargo.lock",
            f'name = "kaspa-hashes"\nversion = "2.0.1"\nsource = "{KASPA_SOURCE}"',
            'name = "kaspa-hashes"\nversion = "2.0.1"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"',
        )
        self.assert_error(
            "Cargo.lock kaspa-hashes 2.0.1", "not resolved from a git source"
        )

    def test_split_graph_duplicate_package(self) -> None:
        dup_source = KASPA_SOURCE.replace(POLICY.kaspa_commit, OTHER_COMMIT)
        self.append(
            "Cargo.lock",
            f'\n[[package]]\nname = "kaspa-core"\nversion = "2.0.2"\nsource = "{dup_source}"\n',
        )
        errors = self.assert_error("Cargo.lock kaspa-core: locked 2 times")
        self.assertTrue(any("split Kaspa source graph" in e for e in errors))

    def test_non_kaspa_name_from_rusty_kaspa_url_checked(self) -> None:
        self.append(
            "Cargo.lock",
            f'\n[[package]]\nname = "workflow-core"\nversion = "0.1.0"\n'
            f'source = "{KASPA_SOURCE.replace("v2.0.1", "v9.9.9")}"\n',
        )
        errors = self.assert_error(
            "Cargo.lock workflow-core 0.1.0", "is not the policy tag"
        )
        self.assertTrue(any("split Kaspa source graph" in e for e in errors))

    def test_direct_dependency_not_locked(self) -> None:
        self.edit("Cargo.lock", 'name = "kaspa-bip32"', 'name = "renamed-bip32"')
        self.assert_error("Cargo.lock kaspa-bip32: direct dependency not locked")


class SilverScriptDriftTest(Fixture):
    def test_workspace_rev_drift(self) -> None:
        self.edit(
            "Cargo.toml",
            f'rev = "{POLICY.silverscript_commit}"',
            f'rev = "{OTHER_COMMIT}"',
        )
        self.assert_error(
            "workspace dependency silverscript-lang", f"rev '{OTHER_COMMIT}'"
        )

    def test_workspace_branch_instead_of_rev(self) -> None:
        self.edit(
            "Cargo.toml", f'rev = "{POLICY.silverscript_commit}"', 'branch = "master"'
        )
        self.assert_error("silverscript-lang", "unexpected keys ['branch']")

    def test_locked_commit_drift(self) -> None:
        self.edit(
            "Cargo.lock",
            SS_SOURCE,
            SS_SOURCE.replace(f"#{POLICY.silverscript_commit}", f"#{OTHER_COMMIT}"),
        )
        self.assert_error("Cargo.lock silverscript-lang", f"commit '{OTHER_COMMIT}'")

    def test_locked_rev_query_drift(self) -> None:
        self.edit(
            "Cargo.lock",
            SS_SOURCE,
            SS_SOURCE.replace(f"?rev={POLICY.silverscript_commit}", "?branch=master"),
        )
        self.assert_error("Cargo.lock silverscript-lang", "is not the policy rev")

    def test_locked_missing(self) -> None:
        self.edit(
            "Cargo.lock", 'name = "silverscript-lang"', 'name = "silverscript-other"'
        )
        self.assert_error("silverscript-lang: locked 0 times")

    def test_member_bypass(self) -> None:
        self.edit(
            "modules/silverc-deployer/Cargo.toml",
            "silverscript-lang.workspace = true",
            f'silverscript-lang = {{ git = "{POLICY.silverscript_url}", branch = "master" }}',
        )
        self.assert_error(
            "silverc-deployer/Cargo.toml [dependencies] silverscript-lang", "inherit"
        )


class ProofIdentityTest(Fixture):
    def test_threat_proof_commit_drift(self) -> None:
        self.edit(
            vtp.THREAT_PROOF_LIB,
            f'RUSTY_KASPA_COMMIT: &str = "{POLICY.proof_kaspa_commit}"',
            f'RUSTY_KASPA_COMMIT: &str = "{OTHER_COMMIT}"',
        )
        self.assert_error("RUSTY_KASPA_COMMIT", "artifact-identity pin")

    def test_threat_proof_tag_drift(self) -> None:
        self.edit(
            vtp.THREAT_PROOF_LIB,
            'RUSTY_KASPA_TAG: &str = "v2.0.1"',
            'RUSTY_KASPA_TAG: &str = "v2.0.2"',
        )
        self.assert_error("RUSTY_KASPA_TAG 'v2.0.2'", "artifact-identity pin")

    def test_threat_proof_duplicate_constant(self) -> None:
        self.append(
            vtp.THREAT_PROOF_LIB, '\npub const RUSTY_KASPA_TAG: &str = "v2.0.1";\n'
        )
        self.assert_error("expected exactly one RUSTY_KASPA_TAG, found 2")

    def test_active_pin_change_does_not_move_identity(self) -> None:
        data = self.policy_data()
        data["threat_proof_artifact_identity"]["rusty_kaspa_commit"] = OTHER_COMMIT
        self.write_policy(data)
        self.assert_error(
            "RUSTY_KASPA_COMMIT", f"artifact-identity pin '{OTHER_COMMIT}'"
        )


class RelationIdentityTest(Fixture):
    PY = vtp.RELATION_MANIFEST_PY
    TAG_LINE = f'RUSTY_KASPA_TAG = "{POLICY.proof_kaspa_tag}"'
    COMMIT_LINE = f'RUSTY_KASPA_COMMIT = "{POLICY.proof_kaspa_commit}"'

    def assert_only_relation_errors(self, *expected: str) -> None:
        errors = self.errors()
        self.assertEqual(errors, sorted(errors))
        self.assertEqual(errors, sorted(f"{self.PY.as_posix()}: {e}" for e in expected))

    def test_python_tag_drift(self) -> None:
        self.edit(self.PY, self.TAG_LINE, 'RUSTY_KASPA_TAG = "v2.0.2"')
        self.assert_only_relation_errors(
            "RUSTY_KASPA_TAG does not match artifact-identity pin"
        )

    def test_python_commit_drift(self) -> None:
        self.edit(self.PY, self.COMMIT_LINE, f'RUSTY_KASPA_COMMIT = "{OTHER_COMMIT}"')
        errors = self.errors()
        self.assertNotIn(OTHER_COMMIT, "\n".join(errors))
        self.assertIn(
            f"{self.PY.as_posix()}: RUSTY_KASPA_COMMIT does not match "
            "artifact-identity pin",
            errors,
        )

    def test_python_both_drift_sorted(self) -> None:
        self.edit(self.PY, self.TAG_LINE, 'RUSTY_KASPA_TAG = "v9.9.9"')
        self.edit(self.PY, self.COMMIT_LINE, f'RUSTY_KASPA_COMMIT = "{OTHER_COMMIT}"')
        self.assert_only_relation_errors(
            "RUSTY_KASPA_COMMIT does not match artifact-identity pin",
            "RUSTY_KASPA_TAG does not match artifact-identity pin",
        )

    def test_python_missing_constant(self) -> None:
        self.edit(self.PY, self.TAG_LINE + "\n", "")
        self.assert_only_relation_errors(
            "expected exactly one RUSTY_KASPA_TAG, found 0"
        )

    def test_python_duplicate_constant(self) -> None:
        self.append(self.PY, f"\n{self.COMMIT_LINE}\n")
        self.assert_only_relation_errors(
            "expected exactly one RUSTY_KASPA_COMMIT, found 2"
        )

    def test_python_shadowing_binding_counts_as_duplicate(self) -> None:
        self.append(self.PY, "\ndef _f(RUSTY_KASPA_TAG: str) -> None:\n    pass\n")
        self.assert_only_relation_errors(
            "expected exactly one RUSTY_KASPA_TAG, found 2"
        )

    def test_python_malformed_assignment_forms(self) -> None:
        pin = POLICY.proof_kaspa_tag
        for form in (
            f'RUSTY_KASPA_TAG: str = "{pin}"',
            f'RUSTY_KASPA_TAG = b"{pin}"',
            f'RUSTY_KASPA_TAG = "{pin}".strip()',
            f'RUSTY_KASPA_TAG = X = "{pin}"',
            f'RUSTY_KASPA_TAG, X = "{pin}", 1',
            f'if True:\n    RUSTY_KASPA_TAG = "{pin}"',
        ):
            with self.subTest(form=form):
                shutil.copyfile(REPO / self.PY, self.root / self.PY)
                self.edit(self.PY, self.TAG_LINE, form)
                self.assert_only_relation_errors(
                    "RUSTY_KASPA_TAG must be a single module-level string assignment"
                )

    def test_python_invalid_source(self) -> None:
        self.append(self.PY, "\ndef (:\n")
        self.assert_only_relation_errors("invalid Python source")

    def test_python_file_missing(self) -> None:
        (self.root / self.PY).unlink()
        self.assert_only_relation_errors("file missing")

    def test_identity_move_flags_both_sources(self) -> None:
        data = self.policy_data()
        data["threat_proof_artifact_identity"]["rusty_kaspa_tag"] = "v2.0.2"
        self.write_policy(data)
        errors = self.errors()
        self.assertEqual(errors, sorted(errors))
        self.assertIn(
            f"{self.PY.as_posix()}: RUSTY_KASPA_TAG does not match "
            "artifact-identity pin",
            errors,
        )
        self.assertTrue(
            any(e.startswith(vtp.THREAT_PROOF_LIB.as_posix()) for e in errors)
        )


class PolicyValidationTest(Fixture):
    def assert_policy_error(self, text: str, fragment: str) -> None:
        with self.assertRaises(vtp.PolicyError) as ctx:
            vtp.parse_policy(text)
        self.assertIn(fragment, str(ctx.exception))
        (self.root / vtp.DEFAULT_POLICY).write_text(text, encoding="utf-8")
        self.assertEqual(self.errors(), [str(ctx.exception)])

    def mutated(self, section: str | None, key: str, value: Any) -> str:
        data = self.policy_data()
        (data if section is None else data[section])[key] = value
        return json.dumps(data)

    def test_invalid_json(self) -> None:
        self.assert_policy_error("{", "invalid JSON")

    def test_duplicate_key(self) -> None:
        text = POLICY_PATH.read_text(encoding="utf-8").replace(
            '"schema_version": 1,', '"schema_version": 1,\n  "schema_version": 1,'
        )
        self.assert_policy_error(text, "duplicate key 'schema_version'")

    def test_duplicate_direct_dependency(self) -> None:
        deps = [*POLICY.kaspa_direct, POLICY.kaspa_direct[-1]]
        self.assert_policy_error(
            self.mutated("rusty_kaspa", "direct_dependencies", deps), "duplicate direct"
        )

    def test_unsorted_direct_dependencies(self) -> None:
        deps = list(reversed(POLICY.kaspa_direct))
        self.assert_policy_error(
            self.mutated("rusty_kaspa", "direct_dependencies", deps), "sorted"
        )

    def test_non_kaspa_direct_dependency(self) -> None:
        deps = sorted([*POLICY.kaspa_direct, "serde"])
        self.assert_policy_error(
            self.mutated("rusty_kaspa", "direct_dependencies", deps), "prefix"
        )

    def test_extra_key(self) -> None:
        self.assert_policy_error(
            self.mutated(None, "status", "ok"), "unexpected ['status']"
        )

    def test_missing_key(self) -> None:
        data = self.policy_data()
        del data["silverscript"]["commit"]
        self.assert_policy_error(json.dumps(data), "missing ['commit']")

    def test_bad_commit_format(self) -> None:
        self.assert_policy_error(
            self.mutated("rusty_kaspa", "commit", "CFAFEB4C"), "invalid format"
        )

    def test_bad_url_format(self) -> None:
        self.assert_policy_error(
            self.mutated(
                "rusty_kaspa", "url", "http://github.com/kaspanet/rusty-kaspa.git"
            ),
            "rusty_kaspa.url has invalid format",
        )

    def test_bool_schema_version(self) -> None:
        self.assert_policy_error(
            self.mutated(None, "schema_version", True), "schema_version"
        )

    def test_wrong_policy_id(self) -> None:
        self.assert_policy_error(self.mutated(None, "policy_id", "x"), "policy_id")

    def test_nan_rejected(self) -> None:
        self.assert_policy_error('{"schema_version": NaN}', "non-finite")

    def test_missing_policy_file(self) -> None:
        (self.root / vtp.DEFAULT_POLICY).unlink()
        self.assertEqual(self.errors(), ["policy: file missing"])


class CiRegistrationTest(unittest.TestCase):
    def test_all_workflow_jobs_pin_validated_runner_baseline(self) -> None:
        import yaml  # type: ignore[import-untyped]

        for path in sorted((REPO / ".github/workflows").iterdir()):
            if path.suffix not in {".yml", ".yaml"}:
                continue
            jobs = yaml.safe_load(path.read_text(encoding="utf-8"))["jobs"]
            self.assertTrue(jobs, path.name)
            for name, job in jobs.items():
                with self.subTest(workflow=path.name, job=name):
                    self.assertEqual(job["runs-on"], "ubuntu-24.04")

    def test_workflow_parses_and_gates_rust_jobs(self) -> None:
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError:  # pragma: no cover - CI installs PyYAML for this job
            self.fail("PyYAML is required for the workflow registration test")
        workflow = yaml.safe_load(
            (REPO / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        )
        jobs = workflow["jobs"]
        gate = jobs["toolchain-pins"]
        commands = "\n".join(step.get("run", "") for step in gate["steps"])
        self.assertIn("python3 scripts/verify_toolchain_pins.py", commands)
        self.assertIn("scripts.test_toolchain_pins", commands)

        def upstream(name: str) -> set[str]:
            needs = jobs[name].get("needs", [])
            direct = {needs} if isinstance(needs, str) else set(needs)
            return direct.union(*(upstream(dep) for dep in direct))

        cargo_jobs = [
            name
            for name, job in jobs.items()
            if any("cargo " in step.get("run", "") for step in job.get("steps", []))
        ]
        self.assertGreaterEqual(len(cargo_jobs), 3)
        for name in cargo_jobs:
            self.assertIn("toolchain-pins", upstream(name), f"{name} is not gated")


class NoClaimLanguageTest(unittest.TestCase):
    """Re-runs the failure suites and scans every emitted line for claim terms."""

    def test_emitted_messages_contain_no_claims(self) -> None:
        suite = unittest.TestSuite()
        loader = unittest.TestLoader()
        for case in (
            CargoTomlDriftTest,
            CargoLockDriftTest,
            SilverScriptDriftTest,
            ProofIdentityTest,
            RelationIdentityTest,
            PolicyValidationTest,
        ):
            suite.addTests(loader.loadTestsFromTestCase(case))
        EMITTED.clear()
        result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
        self.assertTrue(result.wasSuccessful())
        self.assertGreater(len(EMITTED), 30)
        for output in EMITTED:
            lowered = output.lower()
            for term in FORBIDDEN_CLAIM_TERMS:
                self.assertNotIn(term, lowered, output)


if __name__ == "__main__":
    unittest.main()
