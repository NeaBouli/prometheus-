#!/usr/bin/env python3
"""Regression tests for the Prometheus autodidactic workflow helper."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
AUTODIDACTIC_PATH = REPO_ROOT / "scripts" / "autodidactic.py"

spec = importlib.util.spec_from_file_location("autodidactic", AUTODIDACTIC_PATH)
autodidactic = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(autodidactic)


class AutodidacticTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="prometheus-autodidactic-test.")
        self.repo = Path(self.tmp.name)
        self.memory = self.repo / "memory"
        self.memory.mkdir()
        self._write("MEMO.md", "## ARCHITEKTUR-ENTSCHEIDUNGEN\nKeep KAS/PROM split.\n\n## TOKEN-KLARSTELLUNG\nPROM earned-only.\n\n## CODE-STANDARDS\nSmall patches.\n")
        self._write("SCHEMA.md", "## KRITISCHE KLARSTELLUNG\nstruct Validator\nstruct Guardian\n")
        self._write("API.md", "## Validator API\nregisterValidator\n")
        self._write("AUDIT.md", "## AUDIT QUEUE\n\n")
        self._write("ERRORS.md", "## BEKANNTE FEHLER-MUSTER\n- Keep secrets out.\n")
        self._write("SPRINTS.md", "## Sprint 2\nValidator connection work.\n")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write(self, name: str, content: str) -> None:
        (self.memory / name).write_text(content, encoding="utf-8")

    def _auto(self):
        return autodidactic.PrometheusAutodidactic(str(self.repo))

    def test_load_all_memory_uses_empty_string_for_missing_files(self) -> None:
        self._write("TODO.md", "")
        self._write("STATUS.md", "")

        memory = self._auto().load_all_memory()

        self.assertEqual(memory["memo"].splitlines()[0], "## ARCHITEKTUR-ENTSCHEIDUNGEN")
        self.assertEqual(memory["api"], "## Validator API\nregisterValidator\n")

    def test_next_task_honors_priority_and_padded_dependency_rows(self) -> None:
        self._write(
            "TODO.md",
            "\n".join(
                [
                    "- [ ] [P1] Lower priority task | Core Dev | -",
                    "- [ ] [P0] Ready deploy task | Core Dev | DeployPreflight",
                    "- [ ] [P0] Blocked deploy task | Core Dev | MissingDependency",
                ]
            ),
        )
        self._write(
            "STATUS.md",
            "| Modul             | Status   | Progress | Last Update | Audit | Testnet-Adresse |\n"
            "|-------------------|----------|----------|-------------|-------|-----------------|\n"
            "| DeployPreflight   | ACCEPTED | 100%     | 2026-07-12  | -     | -               |\n",
        )

        task = self._auto().get_next_task()

        self.assertIsNotNone(task)
        self.assertEqual(task["task"], "Ready deploy task")
        self.assertTrue(task["deps_met"])

    def test_mark_completed_handles_in_progress_tasks(self) -> None:
        self._write("TODO.md", "- [~] [P0] Autodidactic tests | Codex | memory/-Dateien\n")
        self._write("STATUS.md", "")

        self._auto().mark_task_completed("Autodidactic tests")

        todo = (self.memory / "TODO.md").read_text(encoding="utf-8")
        self.assertIn("- [x] [P0] Autodidactic tests | Codex | memory/-Dateien | Completed:", todo)
        self.assertNotIn("- [~]", todo)

    def test_update_module_status_replaces_padded_table_row(self) -> None:
        self._write("TODO.md", "")
        self._write(
            "STATUS.md",
            "| Modul                        | Status          | Progress | Last Update | Audit        | Testnet-Adresse |\n"
            "|------------------------------|-----------------|----------|-------------|--------------|-----------------|\n"
            "| scripts/autodidactic.py      | DONE            | 100%     | 2026-03-21  | -            | -               |\n",
        )

        self._auto().update_module_status("scripts/autodidactic.py", "ACCEPTED", progress=100)

        status = (self.memory / "STATUS.md").read_text(encoding="utf-8")
        self.assertEqual(status.count("scripts/autodidactic.py"), 1)
        self.assertIn("| scripts/autodidactic.py | ACCEPTED | 100% |", status)

    def test_detect_blockers_reports_blocked_tasks_and_open_errors(self) -> None:
        self._write("TODO.md", "- [!] [P0] Chain deploy | Codex | external | BLOCKED: no orchestrator\n")
        self._write("STATUS.md", "")
        self._write("ERRORS.md", "| 2026-07-12 | deploy | missing path | pending | OPEN |\n")

        blockers = self._auto().detect_blockers()

        self.assertEqual(blockers["count"], 2)
        self.assertEqual({item["type"] for item in blockers["blockers"]}, {"blocked_task", "open_error"})

    def test_cli_get_next_task_outputs_json(self) -> None:
        self._write("TODO.md", "- [ ] [P0] CLI smoke | Codex | -\n")
        self._write("STATUS.md", "")

        auto = self._auto()
        task = auto.get_next_task()

        self.assertEqual(json.loads(json.dumps(task))["task"], "CLI smoke")


if __name__ == "__main__":
    unittest.main()
