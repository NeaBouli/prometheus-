#!/usr/bin/env python3
"""
PROMETHEUS – Autodidactic Module
Version: 1.0

Selbst-lernendes Gedächtnis-System für den autonomen Entwicklungs-Workflow.
Liest alle Memory-Dateien, ermittelt nächste Tasks, aktualisiert Status.
Wird von claude-code-start.sh bei jedem Start aufgerufen.

Usage:
    python3 autodidactic.py --repo <path> --action <action> [--task <task>] [--result <result>]
"""

import os
import re
import sys
import json
import argparse
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any


# ─── Farben für Terminal ──────────────────────────────────────────────────────
class Color:
    GREEN  = '\033[0;32m'
    RED    = '\033[0;31m'
    YELLOW = '\033[1;33m'
    BLUE   = '\033[0;34m'
    CYAN   = '\033[0;36m'
    BOLD   = '\033[1m'
    NC     = '\033[0m'


def cprint(msg: str, color: str = Color.NC) -> None:
    print(f"{color}{msg}{Color.NC}", flush=True)


# ─── Hauptklasse ─────────────────────────────────────────────────────────────
class PrometheusAutodidactic:
    """
    Herzstück des autonomen Entwicklungs-Workflows.
    Verwaltet den gesamten Kontext und das Gedächtnis des Projekts.
    """

    def __init__(self, repo_path: str = "."):
        self.repo = Path(repo_path).resolve()
        self.memory_dir = self.repo / "memory"
        self.modules_dir = self.repo / "modules"
        self.logs_dir = self.repo / "logs"

        # Memory-Dateien
        self.memory_files = {
            "memo":    self.memory_dir / "MEMO.md",
            "todo":    self.memory_dir / "TODO.md",
            "status":  self.memory_dir / "STATUS.md",
            "audit":   self.memory_dir / "AUDIT.md",
            "schema":  self.memory_dir / "SCHEMA.md",
            "api":     self.memory_dir / "API.md",
            "errors":  self.memory_dir / "ERRORS.md",
            "sprints": self.memory_dir / "SPRINTS.md",
        }

        self.memory: Dict[str, str] = {}

    # ─── Memory Laden ─────────────────────────────────────────────────────────

    def load_all_memory(self) -> Dict[str, str]:
        """Lädt alle Memory-Dateien in den internen Zustand."""
        for name, path in self.memory_files.items():
            if path.exists():
                with open(path, 'r', encoding='utf-8') as f:
                    self.memory[name] = f.read()
            else:
                self.memory[name] = ""
        return self.memory

    def _read_file(self, path: Path) -> str:
        if path.exists():
            with open(path, 'r', encoding='utf-8') as f:
                return f.read()
        return ""

    def _write_file(self, path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)

    def _append_file(self, path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'a', encoding='utf-8') as f:
            f.write(content)

    # ─── Task Management ──────────────────────────────────────────────────────

    def get_next_task(self) -> Optional[Dict[str, Any]]:
        """
        Ermittelt die nächste zu bearbeitende Task aus TODO.md.
        Berücksichtigt Prioritäten und Dependencies.
        """
        self.load_all_memory()
        todo_content = self.memory.get("todo", "")

        tasks = []
        pattern = r'- \[ \] \[(P[0-3])\] (.+?) \| (.+?) \| (.+?)$'

        for line in todo_content.split('\n'):
            match = re.search(pattern, line.strip())
            if match:
                priority, task_desc, owner, deps = match.groups()
                deps_met = self._check_dependencies(deps.strip())
                tasks.append({
                    "priority": priority,
                    "task": task_desc.strip(),
                    "owner": owner.strip(),
                    "dependencies": deps.strip(),
                    "deps_met": deps_met,
                    "line": line
                })

        # Sortiere: P0 zuerst, dann P1, P2, P3
        priority_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
        tasks.sort(key=lambda x: priority_order.get(x["priority"], 4))

        # Erste Task mit erfüllten Dependencies
        for task in tasks:
            if task["deps_met"]:
                return task

        return None

    def _check_dependencies(self, deps: str) -> bool:
        """Prüft ob alle Dependencies in STATUS.md als DONE/ACCEPTED markiert sind."""
        if not deps or deps == "-":
            return True

        status_content = self.memory.get("status", "")
        required = [d.strip() for d in deps.split(',')]

        for dep in required:
            if not dep:
                continue
            # Prüfe ob Dependency in STATUS.md als DONE oder ACCEPTED markiert
            pattern = rf'\| {re.escape(dep)} \| (DONE|ACCEPTED) \|'
            if not re.search(pattern, status_content):
                return False
        return True

    def get_all_pending_tasks(self) -> List[Dict[str, Any]]:
        """Gibt alle offenen Tasks zurück."""
        self.load_all_memory()
        todo_content = self.memory.get("todo", "")

        tasks = []
        pattern = r'- \[ \] \[(P[0-3])\] (.+?) \| (.+?) \| (.+?)$'

        for line in todo_content.split('\n'):
            match = re.search(pattern, line.strip())
            if match:
                priority, task_desc, owner, deps = match.groups()
                tasks.append({
                    "priority": priority,
                    "task": task_desc.strip(),
                    "owner": owner.strip(),
                    "dependencies": deps.strip(),
                })

        return tasks

    # ─── Status Updates ───────────────────────────────────────────────────────

    def mark_task_completed(self, task_desc: str, result: str = "success") -> None:
        """Markiert eine Task in TODO.md als erledigt."""
        todo_content = self._read_file(self.memory_files["todo"])

        # Ersetze [ ] durch [x]
        new_content = re.sub(
            rf'- \[ \] (\[P[0-3]\] {re.escape(task_desc)}.*?)$',
            rf'- [x] \1 | Completed: {datetime.now().strftime("%Y-%m-%d")}',
            todo_content,
            flags=re.MULTILINE
        )

        self._write_file(self.memory_files["todo"], new_content)

    def mark_task_in_progress(self, task_desc: str) -> None:
        """Markiert eine Task in TODO.md als in Bearbeitung."""
        todo_content = self._read_file(self.memory_files["todo"])

        new_content = re.sub(
            rf'- \[ \] (\[P[0-3]\] {re.escape(task_desc)}.*?)$',
            rf'- [~] \1 | Started: {datetime.now().strftime("%Y-%m-%d %H:%M")}',
            todo_content,
            flags=re.MULTILINE
        )

        self._write_file(self.memory_files["todo"], new_content)

    def mark_task_blocked(self, task_desc: str, blocker: str) -> None:
        """Markiert eine Task als blockiert."""
        todo_content = self._read_file(self.memory_files["todo"])

        new_content = re.sub(
            rf'- \[ \] (\[P[0-3]\] {re.escape(task_desc)}.*?)$',
            rf'- [!] \1 | BLOCKED: {blocker}',
            todo_content,
            flags=re.MULTILINE
        )

        self._write_file(self.memory_files["todo"], new_content)

        # Auch in MEMO.md Blockaden-Sektion eintragen
        memo_content = self._read_file(self.memory_files["memo"])
        if "## BLOCKADEN" in memo_content:
            new_memo = memo_content.replace(
                "Keine bekannten Blockaden.",
                f"- [{datetime.now().strftime('%Y-%m-%d')}] {task_desc}: {blocker}"
            )
            self._write_file(self.memory_files["memo"], new_memo)

    def update_module_status(self, module: str, status: str,
                              progress: int = 100,
                              address: str = "-") -> None:
        """Aktualisiert den Status eines Moduls in STATUS.md."""
        status_content = self._read_file(self.memory_files["status"])

        today = datetime.now().strftime('%Y-%m-%d')

        # Prüfe ob Modul bereits existiert
        pattern = rf'\| {re.escape(module)} \| \S+ \| \d+% \| .+ \| .+ \|'
        new_row = f"| {module} | {status} | {progress}% | {today} | PENDING_AUDIT | {address} |"

        if re.search(pattern, status_content):
            new_content = re.sub(pattern, new_row, status_content)
        else:
            # Finde richtige Tabellen-Sektion und füge ein
            new_content = status_content + f"\n{new_row}"

        self._write_file(self.memory_files["status"], new_content)

    # ─── Error Logging ────────────────────────────────────────────────────────

    def log_error(self, module: str, error_msg: str,
                  solution: str = "pending") -> None:
        """Dokumentiert einen Fehler in ERRORS.md."""
        today = datetime.now().strftime('%Y-%m-%d')
        new_line = f"| {today} | {module} | {error_msg[:80]} | {solution} | OPEN |\n"
        self._append_file(self.memory_files["errors"], new_line)

    # ─── Audit Management ─────────────────────────────────────────────────────

    def add_audit_pending(self, module: str, version: str = "-") -> None:
        """Fügt ein Modul zur Audit-Queue hinzu."""
        today = datetime.now().strftime('%Y-%m-%d')
        new_line = f"| {module} | {version} | {today} | - | PENDING | Bereit für Review durch Claude |\n"

        audit_content = self._read_file(self.memory_files["audit"])

        # Füge zur AUDIT QUEUE Sektion hinzu
        if "## AUDIT QUEUE" in audit_content:
            new_content = audit_content.replace(
                "Aktuell leer – noch kein Code-Modul fertiggestellt.",
                f"{new_line}\nAktuell leer – noch kein Code-Modul fertiggestellt."
                if "Aktuell leer" in audit_content else new_line
            )
        else:
            new_content = audit_content + f"\n## AUDIT QUEUE\n\n{new_line}"

        self._write_file(self.memory_files["audit"], new_content)

    # ─── Kontext für Claude Code ──────────────────────────────────────────────

    def get_task_context(self, task: str) -> str:
        """
        Sammelt den vollständigen, relevanten Kontext für eine Task.
        Dieser Kontext wird an Claude Code übergeben.
        """
        self.load_all_memory()
        context_parts = []

        # 1. Architekturentscheidungen (KRITISCH)
        memo = self.memory.get("memo", "")
        arch_match = re.search(
            r'## ARCHITEKTUR-ENTSCHEIDUNGEN.*?(?=\n## )',
            memo, re.DOTALL
        )
        if arch_match:
            context_parts.append(
                f"# ARCHITEKTUR-ENTSCHEIDUNGEN (unveränderlich)\n{arch_match.group(0)}"
            )

        # 2. Token-Klarstellung
        token_match = re.search(
            r'## TOKEN-KLARSTELLUNG.*?(?=\n## )',
            memo, re.DOTALL
        )
        if token_match:
            context_parts.append(
                f"# TOKEN-KLARSTELLUNG (KRITISCH)\n{token_match.group(0)}"
            )

        # 3. Relevante Schemas
        schema = self.memory.get("schema", "")
        # Finde Schemas die zum Task passen
        schema_keywords = self._extract_keywords(task)
        relevant_schemas = self._extract_relevant_sections(schema, schema_keywords)
        if relevant_schemas:
            context_parts.append(f"# RELEVANTE SCHEMAS\n{relevant_schemas[:3000]}")

        # 4. API-Definitionen
        api = self.memory.get("api", "")
        relevant_api = self._extract_relevant_sections(api, schema_keywords)
        if relevant_api:
            context_parts.append(f"# RELEVANTE API-DEFINITIONEN\n{relevant_api[:2000]}")

        # 5. Bekannte Fehler-Muster (IMMER vollständig)
        errors = self.memory.get("errors", "")
        patterns_match = re.search(r'## BEKANNTE FEHLER-MUSTER.*?(?=\n## |\Z)', errors, re.DOTALL)
        if patterns_match:
            context_parts.append(f"# BEKANNTE FEHLER-MUSTER (VERMEIDEN)\n{patterns_match.group(0)}")

        # 6. Code-Standards
        standards_match = re.search(r'## CODE-STANDARDS.*?(?=\n## |\Z)', memo, re.DOTALL)
        if standards_match:
            context_parts.append(f"# CODE-STANDARDS (einhalten)\n{standards_match.group(0)}")

        # 7. Sprint-Details für diese Task
        sprints = self.memory.get("sprints", "")
        sprint_details = self._find_sprint_for_task(sprints, task)
        if sprint_details:
            context_parts.append(f"# SPRINT DETAILS FÜR DIESE TASK\n{sprint_details}")

        return "\n\n---\n\n".join(context_parts)

    def _extract_keywords(self, text: str) -> List[str]:
        """Extrahiert relevante Keywords aus einem Task-Text."""
        # Entferne häufige Wörter
        stopwords = {'und', 'oder', 'mit', 'für', 'auf', 'in', 'die', 'der',
                     'das', 'ein', 'eine', 'ist', 'sind', 'wird', 'werden',
                     'sprint', 'task', 'schreiben', 'erstellen', 'implementieren'}

        words = re.findall(r'\b[A-Za-z][A-Za-z0-9_]{2,}\b', text.lower())
        return [w for w in words if w not in stopwords]

    def _extract_relevant_sections(self, content: str, keywords: List[str]) -> str:
        """Extrahiert relevante Abschnitte basierend auf Keywords."""
        if not keywords:
            return content[:2000]

        sections = re.split(r'\n#{1,3} ', content)
        relevant = []

        for section in sections:
            section_lower = section.lower()
            if any(kw in section_lower for kw in keywords):
                relevant.append(section[:800])

        return '\n\n'.join(relevant[:5]) if relevant else content[:1500]

    def _find_sprint_for_task(self, sprints: str, task: str) -> str:
        """Findet die Sprint-Details für eine bestimmte Task."""
        task_keywords = self._extract_keywords(task)
        lines = sprints.split('\n')
        relevant_lines = []
        in_relevant_section = False

        for line in lines:
            line_lower = line.lower()
            if any(kw in line_lower for kw in task_keywords):
                in_relevant_section = True
            if in_relevant_section:
                relevant_lines.append(line)
                if len(relevant_lines) > 20:
                    break

        return '\n'.join(relevant_lines[:20])

    # ─── Anzeige-Funktionen ───────────────────────────────────────────────────

    def show_status(self) -> None:
        """Zeigt den aktuellen Projektstatus."""
        self.load_all_memory()
        status = self.memory.get("status", "")

        cprint("\n📊 PROMETHEUS – Projektstatus", Color.BOLD)
        cprint("=" * 50, Color.BLUE)

        # Zähle Module nach Status
        done = len(re.findall(r'\| DONE \|', status))
        accepted = len(re.findall(r'\| ACCEPTED \|', status))
        pending = len(re.findall(r'\| PENDING \|', status))
        in_progress = len(re.findall(r'\| IN_PROGRESS \|', status))
        blocked = len(re.findall(r'\| BLOCKED \|', status))

        cprint(f"  ✅ DONE/ACCEPTED:   {done + accepted}", Color.GREEN)
        cprint(f"  🔄 IN_PROGRESS:     {in_progress}", Color.CYAN)
        cprint(f"  ⏳ PENDING:         {pending}", Color.YELLOW)
        cprint(f"  ❌ BLOCKED:         {blocked}", Color.RED)

        # Nächste Task
        next_task = self.get_next_task()
        if next_task:
            cprint(f"\n➡️  Nächste Task [{next_task['priority']}]:", Color.BOLD)
            cprint(f"   {next_task['task']}", Color.CYAN)
        else:
            cprint("\n🎉 Keine offenen Tasks! Alle Sprints abgeschlossen.", Color.GREEN)

    def show_summary(self) -> None:
        """Zeigt eine kurze Zusammenfassung."""
        self.load_all_memory()

        todo = self.memory.get("todo", "")
        done_count = len(re.findall(r'- \[x\]', todo))
        pending_count = len(re.findall(r'- \[ \]', todo))
        blocked_count = len(re.findall(r'- \[!\]', todo))

        print(f"Tasks: {done_count} erledigt | {pending_count} offen | {blocked_count} blockiert")

        next_task = self.get_next_task()
        if next_task:
            print(f"Nächste Task: [{next_task['priority']}] {next_task['task']}")

    def get_next_actions(self) -> None:
        """Zeigt die empfohlenen nächsten Aktionen."""
        self.load_all_memory()

        # Prüfe auf ausstehende Audits
        audit = self.memory.get("audit", "")
        pending_audits = re.findall(r'\| (.+?) \| .+ \| PENDING \|', audit)

        if pending_audits:
            print(f"→ Audit-Request an Claude senden für: {', '.join(pending_audits[:3])}")
        else:
            next_task = self.get_next_task()
            if next_task:
                print(f"→ Nächste Task starten: [{next_task['priority']}] {next_task['task']}")
            else:
                print("→ Alle Tasks erledigt. Sprint-Review durchführen.")

    def detect_blockers(self) -> Dict[str, Any]:
        """Analysiert den Projektstatus auf Blockaden."""
        self.load_all_memory()

        blockers = []
        todo = self.memory.get("todo", "")
        errors = self.memory.get("errors", "")

        # Finde explizit markierte Blockaden
        blocked_tasks = re.findall(r'- \[!\] \[P[0-3]\] (.+?) \| (.+?) \| BLOCKED: (.+?)$',
                                    todo, re.MULTILINE)
        for task, owner, reason in blocked_tasks:
            blockers.append({
                "type": "blocked_task",
                "task": task,
                "reason": reason,
                "severity": "HIGH"
            })

        # Finde offene Fehler
        open_errors = re.findall(r'\| \d{4}-\d{2}-\d{2} \| (.+?) \| (.+?) \| pending \| OPEN \|',
                                   errors)
        for module, error in open_errors:
            blockers.append({
                "type": "open_error",
                "module": module,
                "error": error,
                "severity": "MEDIUM"
            })

        return {"blockers": blockers, "count": len(blockers)}

    def load_context(self) -> Dict[str, Any]:
        """Lädt den gesamten Kontext (für show_status etc.)."""
        self.load_all_memory()
        return {
            "loaded_files": list(self.memory_files.keys()),
            "total_lines": sum(len(v.split('\n')) for v in self.memory.values()),
            "status": "ok"
        }


# ─── Hauptprogramm ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Prometheus Autodidactic Module',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--repo', default='.', help='Repository-Pfad')
    parser.add_argument('--action', required=True,
                        choices=[
                            'load_context', 'get_next_task', 'show_status',
                            'show_summary', 'get_next_actions', 'detect_blockers',
                            'mark_completed', 'mark_in_progress', 'mark_blocked',
                            'log_error', 'update_status', 'get_task_context',
                            'add_audit_pending'
                        ])
    parser.add_argument('--task', default=None, help='Task-Beschreibung')
    parser.add_argument('--result', default='success', help='Task-Ergebnis')
    parser.add_argument('--error', default=None, help='Fehlerbeschreibung')
    parser.add_argument('--blocker', default=None, help='Blockade-Beschreibung')
    parser.add_argument('--module', default=None, help='Modul-Name')
    parser.add_argument('--status-val', default='DONE', help='Status-Wert')
    parser.add_argument('--address', default='-', help='Contract-Adresse')
    parser.add_argument('--version', default='-', help='Modul-Version')

    args = parser.parse_args()

    auto = PrometheusAutodidactic(repo_path=args.repo)

    try:
        if args.action == 'load_context':
            result = auto.load_context()
            print(json.dumps(result, indent=2))

        elif args.action == 'get_next_task':
            task = auto.get_next_task()
            if task:
                context = auto.get_task_context(task.get('task', ''))
                task['context_preview'] = context[:500] + "..."
                print(json.dumps(task, indent=2, ensure_ascii=False))
            else:
                print(json.dumps({"status": "NO_TASKS", "message": "Alle Tasks erledigt"}))

        elif args.action == 'show_status':
            auto.show_status()

        elif args.action == 'show_summary':
            auto.show_summary()

        elif args.action == 'get_next_actions':
            auto.get_next_actions()

        elif args.action == 'detect_blockers':
            result = auto.detect_blockers()
            print(json.dumps(result, indent=2, ensure_ascii=False))

        elif args.action == 'mark_completed':
            if not args.task:
                print(json.dumps({"error": "--task required"})); sys.exit(1)
            auto.mark_task_completed(args.task, args.result)
            print(json.dumps({"status": "ok", "message": f"Task '{args.task}' als erledigt markiert"}))

        elif args.action == 'mark_in_progress':
            if not args.task:
                print(json.dumps({"error": "--task required"})); sys.exit(1)
            auto.mark_task_in_progress(args.task)
            print(json.dumps({"status": "ok"}))

        elif args.action == 'mark_blocked':
            if not args.task:
                print(json.dumps({"error": "--task required"})); sys.exit(1)
            auto.mark_task_blocked(args.task, args.blocker or "Unbekannte Blockade")
            print(json.dumps({"status": "ok"}))

        elif args.action == 'log_error':
            if not args.module:
                print(json.dumps({"error": "--module required"})); sys.exit(1)
            auto.log_error(args.module, args.error or "Unbekannter Fehler")
            print(json.dumps({"status": "ok"}))

        elif args.action == 'update_status':
            if not args.module:
                print(json.dumps({"error": "--module required"})); sys.exit(1)
            auto.update_module_status(args.module, args.status_val,
                                       address=args.address)
            print(json.dumps({"status": "ok"}))

        elif args.action == 'get_task_context':
            if not args.task:
                print(json.dumps({"error": "--task required"})); sys.exit(1)
            context = auto.get_task_context(args.task)
            print(context)

        elif args.action == 'add_audit_pending':
            if not args.module:
                print(json.dumps({"error": "--module required"})); sys.exit(1)
            auto.add_audit_pending(args.module, args.version)
            print(json.dumps({"status": "ok"}))

    except Exception as e:
        print(json.dumps({"error": str(e), "type": type(e).__name__}), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
