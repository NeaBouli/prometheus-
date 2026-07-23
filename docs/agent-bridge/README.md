# Agent Bridge

Lokaler Kommunikations- und Handover-Bereich fuer dieses Projekt.

Startpunkt fuer Codex/Claude Code:

1. CODEX_BRIDGE.md
2. COOPERATION_RULES.md
3. CLAUDE_CODE_README.md

Keine Secrets, Tokens, Passwoerter, privaten Keys oder Wallet-Daten in diese Bridge schreiben.

Aktiver Handover: GH-55 ist als exact main `c8a6cb8` verifiziert. Issue #58 implementiert auf `feature/GH-58-threat-hint-verifier-ingress` den separaten owner-only Verifier-IPC, trusted Network/Domain Binding, persistente Freshness/Replay-Abwehr und einen atomaren dauerhaften Analyzer-Outbox. Development-Stubs bleiben gesperrt; ohne unabhängig freigegebenen echten Groth16-Verifier antwortet der operated Sidecar fail-closed mit `busy` und behauptet keine akzeptierte Analyse. Echte Zwei-Host-Evidence wartet weiterhin auf reparierten `ssh sandbox` Public-Key-Zugriff. Verbindlicher Status und offene Gates stehen in `CODEX_BRIDGE.md`; laufende Schritte stehen in `ACTION_LOG.md`.
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
