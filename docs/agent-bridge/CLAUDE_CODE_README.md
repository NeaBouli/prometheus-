# Claude Code README

Claude Code: Dieser Ordner ist die gemeinsame Kommunikations-Bridge zwischen dir, Codex und Gio.

Zweck: Wir arbeiten ueber Dateien in diesem Ordner zusammen, damit Audit, Entwicklung, Fixes, Rechecks, offene Fragen und Projektstatus nachvollziehbar bleiben.

## Vor jeder Arbeit

1. Lies COOPERATION_RULES.md.
2. Lies PROJECT_STATE.md fuer bekannten Projektstatus.
3. Lies CODEX_FINDINGS.md fuer offene Findings oder Recheck-Anforderungen.
4. Lies CC_RESPONSE.md, falls du an eine vorherige CC-Session anschliesst.
5. Lies TODO.md fuer priorisierte naechste Schritte.

## Wie du mit Codex kommunizierst

- Schreibe Antworten, Fixplaene und Fixberichte in CC_RESPONSE.md.
- Bitte Codex dort um Recheck, wenn du einen Fix umgesetzt hast.
- Nenne Finding-ID, geaenderte Dateien, Commit-SHA falls vorhanden, Tests/Checks und offene Risiken.
- Wenn du eine Codex-Einschaetzung brauchst, formuliere die Frage klar in CC_RESPONSE.md oder QUESTIONS.md.

## Was Codex schreibt

- CODEX_FINDINGS.md: Findings, Severity, Rechecks, VERIFIED_FIXED / PARTIAL / STILL_OPEN / REGRESSION_RISK.
- ACTION_LOG.md: relevante Audit-, Fix- und Statusaktionen.
- PROJECT_STATE.md und TODO.md: nur wenn sich Status oder Prioritaeten wirklich aendern.

## Grenzen

- Keine Secrets lesen oder in Bridge-Dateien schreiben.
- Keine fremden Diffs revertieren.
- Bei Sicherheits-, Crypto-, Contract-, Auth-, Key-Management-, Deployment- oder Release-Fragen konservativ arbeiten und Gio einbeziehen, wenn keine sichere Annahme moeglich ist.
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
