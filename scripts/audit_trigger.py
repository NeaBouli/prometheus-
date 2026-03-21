#!/usr/bin/env python3
"""
PROMETHEUS – Audit Trigger
Version: 1.0

Wird von Claude (Architect) aufgerufen um Audit-Ergebnisse in AUDIT.md zu schreiben.
Aktualisiert automatisch STATUS.md nach dem Audit.

Usage:
    python3 audit_trigger.py --module <name> --result ACCEPTED --comments "..."
    python3 audit_trigger.py --module <name> --result REJECTED --comments "Grund: ..."
    python3 audit_trigger.py --module <name> --result NEEDS_CHANGES --comments "Änderung: ..."
    python3 audit_trigger.py --list-pending
"""

import sys
import re
import argparse
from pathlib import Path
from datetime import datetime


MEMORY_DIR = Path(__file__).parent.parent / "memory"


def read_file(path: Path) -> str:
    if path.exists():
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    return ""


def write_file(path: Path, content: str) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)


def write_audit(module: str, result: str, comments: str,
                version: str = "-", auditor: str = "Claude") -> None:
    """
    Schreibt Audit-Ergebnis in AUDIT.md und aktualisiert STATUS.md.

    Args:
        module:   Name des auditierten Moduls
        result:   ACCEPTED | REJECTED | NEEDS_CHANGES
        comments: Ausführliche Begründung
        version:  Versions-Tag
        auditor:  Name des Auditors (default: Claude)
    """
    audit_path = MEMORY_DIR / "AUDIT.md"
    status_path = MEMORY_DIR / "STATUS.md"
    today = datetime.now().strftime('%Y-%m-%d')

    # ─── AUDIT.md aktualisieren ─────────────────────────────────────────────
    audit_content = read_file(audit_path)

    # Entferne aus AUDIT QUEUE falls vorhanden
    audit_content = re.sub(
        rf'\| {re.escape(module)} \| .+ \| PENDING \| Bereit für Review.*?\n',
        '',
        audit_content
    )

    # Füge zur LOG TABELLE hinzu
    new_log_line = f"| {module} | {version} | {today} | {auditor} | {result} | {comments} |\n"

    # Finde die LOG TABELLE und füge nach dem Header ein
    log_table_pattern = r'(## AUDIT LOG TABELLE\n\|.+?\n\|[-|]+\|\n)'
    match = re.search(log_table_pattern, audit_content, re.DOTALL)

    if match:
        insert_pos = match.end()
        audit_content = audit_content[:insert_pos] + new_log_line + audit_content[insert_pos:]
    else:
        audit_content += f"\n{new_log_line}"

    # Bei REJECTED: Zu REJECTED MODULES hinzufügen
    if result == "REJECTED":
        rejected_entry = f"\n### {module} – {today}\n**Grund:** {comments}\n**Aktion:** Modul komplett neu schreiben.\n"
        if "## REJECTED MODULES" in audit_content:
            audit_content = audit_content.replace(
                "Aktuell keine Rejections.",
                rejected_entry + "\nAktuell keine Rejections."
            )
        else:
            audit_content += f"\n## REJECTED MODULES\n{rejected_entry}"

    # Bei NEEDS_CHANGES: Zu NEEDS_CHANGES Sektion hinzufügen
    elif result == "NEEDS_CHANGES":
        changes_entry = f"\n### {module} – {today}\n{comments}\n"
        if "## NEEDS_CHANGES" in audit_content:
            audit_content = audit_content.replace(
                "Aktuell keine offenen Changes.",
                changes_entry + "\nAktuell keine offenen Changes."
            )

    # Statistik aktualisieren
    accepted_count = len(re.findall(r'\| ACCEPTED \|', audit_content))
    rejected_count = len(re.findall(r'\| REJECTED \|', audit_content))
    needs_changes_count = len(re.findall(r'\| NEEDS_CHANGES \|', audit_content))
    total = accepted_count + rejected_count + needs_changes_count

    if total > 0:
        acceptance_rate = round(accepted_count / total * 100)
    else:
        acceptance_rate = 0

    # Aktualisiere Statistik-Block
    stats_block = f"""## AUDIT STATISTIK

```
Total Audits:     {total}
ACCEPTED:         {accepted_count}
NEEDS_CHANGES:    {needs_changes_count}
REJECTED:         {rejected_count}
Acceptance Rate:  {acceptance_rate}%
```"""

    audit_content = re.sub(
        r'## AUDIT STATISTIK.*?```',
        stats_block,
        audit_content,
        flags=re.DOTALL
    )

    write_file(audit_path, audit_content)
    print(f"✅ AUDIT.md aktualisiert: {module} → {result}")

    # ─── STATUS.md aktualisieren ─────────────────────────────────────────────
    status_content = read_file(status_path)

    # Ersetze PENDING_AUDIT durch Audit-Ergebnis
    new_status_content = re.sub(
        rf'(\| {re.escape(module)} \| )DONE( \| \d+% \| .+? \| )PENDING_AUDIT( \|)',
        rf'\g<1>{result}\g<2>{result}\g<3>',
        status_content
    )

    if new_status_content != status_content:
        write_file(status_path, new_status_content)
        print(f"✅ STATUS.md aktualisiert: {module} → {result}")
    else:
        print(f"⚠️  STATUS.md: Kein Match für '{module}' gefunden (möglicherweise bereits aktualisiert)")


def list_pending_audits() -> None:
    """Listet alle ausstehenden Audit-Anfragen."""
    audit_path = MEMORY_DIR / "AUDIT.md"
    audit_content = read_file(audit_path)

    pending = re.findall(r'\| (.+?) \| .+ \| PENDING \|', audit_content)

    if pending:
        print("\n📋 Ausstehende Audits:")
        for module in pending:
            print(f"  → {module}")
        print()
    else:
        print("\n✅ Keine ausstehenden Audits.\n")


def main():
    parser = argparse.ArgumentParser(
        description='Prometheus Audit Trigger – Wird von Claude (Architect) aufgerufen'
    )
    parser.add_argument('--module', help='Name des zu auditierenden Moduls')
    parser.add_argument('--result',
                        choices=['ACCEPTED', 'REJECTED', 'NEEDS_CHANGES'],
                        help='Audit-Ergebnis')
    parser.add_argument('--comments', default='-', help='Ausführliche Begründung')
    parser.add_argument('--version', default='-', help='Modul-Version')
    parser.add_argument('--auditor', default='Claude', help='Name des Auditors')
    parser.add_argument('--list-pending', action='store_true',
                        help='Zeige alle ausstehenden Audits')

    args = parser.parse_args()

    if args.list_pending:
        list_pending_audits()
        return

    if not args.module or not args.result:
        parser.print_help()
        print("\nFehler: --module und --result sind erforderlich")
        sys.exit(1)

    write_audit(
        module=args.module,
        result=args.result,
        comments=args.comments,
        version=args.version,
        auditor=args.auditor
    )

    print(f"\n{'='*50}")
    print(f"Audit abgeschlossen: {args.module}")
    print(f"Ergebnis: {args.result}")
    if args.result == "ACCEPTED":
        print("→ Nächsten Sprint starten")
    elif args.result == "NEEDS_CHANGES":
        print("→ Änderungen einarbeiten, erneut auditieren")
    elif args.result == "REJECTED":
        print("→ Modul komplett neu schreiben")
    print(f"{'='*50}\n")


if __name__ == "__main__":
    main()
