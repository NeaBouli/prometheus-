#!/usr/bin/env python3
"""
PROMETHEUS – Memory Integrity Check
Wird von GitHub Actions CI/CD ausgeführt.
Prüft ob alle Memory-Dateien vorhanden und valide sind.
"""

import sys
from pathlib import Path

REQUIRED_FILES = [
    "memory/MEMO.md",
    "memory/TODO.md",
    "memory/STATUS.md",
    "memory/AUDIT.md",
    "memory/SCHEMA.md",
    "memory/API.md",
    "memory/ERRORS.md",
    "memory/SPRINTS.md",
]

REQUIRED_SECTIONS = {
    "memory/MEMO.md": ["## ARCHITEKTUR-ENTSCHEIDUNGEN", "## TOKEN-KLARSTELLUNG", "## CODE-STANDARDS"],
    "memory/SCHEMA.md": ["## KRITISCHE KLARSTELLUNG", "struct Validator", "struct Guardian"],
    "memory/TODO.md": ["SPRINT 0", "ABGESCHLOSSEN"],
}

errors = []
repo_root = Path(__file__).parent.parent

print("🔍 Prometheus Memory Integrity Check")
print("=" * 40)

# Prüfe Dateien vorhanden
for file in REQUIRED_FILES:
    path = repo_root / file
    if not path.exists():
        errors.append(f"FEHLT: {file}")
        print(f"  ❌ FEHLT: {file}")
    else:
        size = path.stat().st_size
        print(f"  ✅ {file} ({size} bytes)")

# Prüfe Pflicht-Sektionen
for file, sections in REQUIRED_SECTIONS.items():
    path = repo_root / file
    if not path.exists():
        continue
    content = path.read_text(encoding='utf-8')
    for section in sections:
        if section not in content:
            errors.append(f"{file}: Sektion '{section}' fehlt")
            print(f"  ⚠️  {file}: Sektion '{section}' fehlt")

print("=" * 40)

if errors:
    print(f"❌ {len(errors)} Fehler gefunden:")
    for e in errors:
        print(f"   - {e}")
    sys.exit(1)
else:
    print("✅ Alle Memory-Checks bestanden!")
    sys.exit(0)
