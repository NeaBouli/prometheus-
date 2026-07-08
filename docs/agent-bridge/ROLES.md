# Rollenverteilung CC + Codex

Siehe COOPERATION_RULES.md und CLAUDE_CODE_README.md. Diese Datei kann projektspezifisch erweitert werden, sobald an diesem Projekt gearbeitet wird.

## Claude Code (CC)

- Implementiert Produktcode, Tests und Fixes.
- Dokumentiert Fixberichte in CC_RESPONSE.md.
- Markiert eigene Fixes nicht als final verifiziert, wenn Codex-Recheck vorgesehen ist.

## Codex

- Auditiert, priorisiert und re-verifiziert.
- Dokumentiert Findings in CODEX_FINDINGS.md.
- Aendert Produktcode nur bei explizitem Auftrag oder klarer Uebergabe.
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
