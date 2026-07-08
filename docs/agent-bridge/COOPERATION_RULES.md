# Agent Cooperation Rules

Projekt: prometheus
Lokaler Pfad: /Users/gio/Desktop/repo/prometheus
Angelegt: 2026-05-08

Dieser Ordner ist der gemeinsame Kommunikations- und Arbeitsordner fuer Claude Code, Codex und Gio.
Claude Code und Codex nutzen diese Bridge, um gemeinsam an Projekten zu arbeiten, ohne Kontext zu verlieren oder parallel dieselben Dateien zu ueberschreiben.
Projektcode und Projektdaten werden erst gelesen, wenn konkret an diesem Projekt gearbeitet wird.

## Fuer Claude Code

- Wenn du dieses Projekt bearbeitest, lies zuerst diese Datei und CLAUDE_CODE_README.md.
- Schreibe deine Fixplaene, Rueckfragen an Codex und Fixberichte in CC_RESPONSE.md.
- Lies CODEX_FINDINGS.md vor Fixes und nach Rechecks.
- Aktualisiere ACTION_LOG.md nach relevanten Aktionen.
- Schreibe keine Secrets, Tokens, Keys, Keystore-Daten oder Env-Werte in diese Bridge.
- Wenn Codex ein Finding als STILL_OPEN markiert, bleibt es offen bis Recheck oder Gio-Entscheidung.

## Fuer Codex

- Dokumentiere Findings, Rechecks und Freigaben in CODEX_FINDINGS.md.
- Behandle Produktcode-Diffs von Claude Code oder Gio als fremde Aenderungen: lesen zur Einordnung, nicht revertieren.
- Aendere Produktcode nur bei explizitem Auftrag, klarer Uebergabe oder kleinen eindeutigen Docs-/Bridge-Fixes.

## Arbeitsmodi

- CHAT: Fragen, Recherche, Zusammenfassungen, Erklaerungen.
- EDIT: kleine, klar begrenzte Text-, Config- oder Formatierungsarbeiten.
- BUILD: Feature-/Fix-Arbeit mit Tests und Verifikation.
- AUDIT: Security-/Quality-Review, Findings, Rechecks.
- ARCH: Architektur-/Systemdesign nur bei expliziter Anforderung.
- AGENT: laengere autonome Task-Schleifen mit Bridge-Status.

## Rollen

- Claude Code (CC): Hauptentwickler fuer Produktcode, Refactors, Tests, Builds, Commits und Fixberichte.
- Codex: Auditor/Reviewer, Findings, Rechecks, Status, kleine eindeutige Docs-/Bridge-Fixes.
- Gio: Produkt-, Sicherheits-, Deployment- und Release-Entscheidungen.

## Workflow

1. Vor Arbeit Bridge-Dateien lesen: COOPERATION_RULES.md, CLAUDE_CODE_README.md, PROJECT_STATE.md, TODO.md, QUESTIONS.md falls vorhanden, DECISIONS.md falls vorhanden.
2. Codex dokumentiert Findings und Rechecks in CODEX_FINDINGS.md.
3. CC dokumentiert Fixplaene, geaenderte Dateien, Commits und Tests in CC_RESPONSE.md.
4. ACTION_LOG.md wird bei relevanten Aktionen aktualisiert.
5. PROJECT_STATE.md und TODO.md nur aktualisieren, wenn sich Projektstatus oder Prioritaeten wirklich aendern.

## Sicherheitsgrenzen

- Keine .env-, Secret-, Key-, Keystore-, Wallet-, Dump- oder Backup-Dateien lesen oder ausgeben.
- Keine Secrets in Bridge-Dateien schreiben.
- Keine destruktiven Aktionen, Deployments, Releases, Pushes oder Live-Trading ohne klare Nutzerfreigabe.
- Fremde lokale Diffs nie revertieren; bei Konflikt zuerst Bridge-Notiz oder Rueckfrage.
- Security-, Crypto-, Contract-, Auth-, Multisig- und Key-Management-Aenderungen brauchen Threat Model und explizite Risikoangabe.

## Konfliktregel

- Wenn CC und Codex denselben Produktcodebereich beruehren wuerden, hat die dokumentierte aktive Ownership Vorrang.
- Codex aendert standardmaessig keinen Produktcode, wenn CC aktiv an Fixes arbeitet.
- Bei Widerspruch zwischen Implementierung und Audit-Finding bleibt das Finding offen, bis es verifiziert oder von Gio entschieden ist.
<!-- CODEX_CLAUDE_CODE_TERMINAL_BRIDGE_V1 -->
## Codex -> Claude Code Terminal Bridge

Status: configured on 2026-07-07. Codex must call Claude Code through the local terminal wrapper, not through the Anthropic API.

Use this probe:

```bash
env -u LC_ALL claude-code-terminal --probe
```

Expected output:

```text
claude-code-terminal-ok
```

Send prompts to Claude Code with:

```bash
env -u LC_ALL claude-code-terminal "PROMPT_TEXT"
```

or via stdin:

```bash
printf '%s\n' "PROMPT_TEXT" | env -u LC_ALL claude-code-terminal
```

Rules for all dev agents:

- Do not use the Anthropic API, Anthropic SDK, `ANTHROPIC_API_KEY`, or direct HTTP calls for Codex -> Claude Code handoff.
- Do not use `claude --bare`; bare mode does not read the local claude.ai OAuth/keychain session and will report not logged in.
- Do not use `cc` for Claude Code; on this machine `cc` is the C compiler.
- The Claude Code CLI command is `claude`; the stable wrapper is `/Users/gio/.local/bin/claude-code-terminal`.
- If a probe returns `401 Invalid authentication credentials`, the integration is using the wrong path: API instead of terminal.
- Keep secrets, tokens, passwords, private keys, and keychain material out of bridge files.
<!-- /CODEX_CLAUDE_CODE_TERMINAL_BRIDGE_V1 -->
