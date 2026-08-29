# Agent Bridge

Lokaler Kommunikations- und Handover-Bereich fuer dieses Projekt.

Startpunkt fuer Codex/Claude Code:

1. CODEX_BRIDGE.md
2. COOPERATION_RULES.md
3. CLAUDE_CODE_README.md

Keine Secrets, Tokens, Passwoerter, privaten Keys oder Wallet-Daten in diese Bridge schreiben.

Aktiver Handover: GH-238 bereitet repository-only eine kontrollierte
distinct-host ThreatHint-v2-Evidenzgrenze vor: challenge-gebundene
Sender-/Guardian-Attestationen, deterministischer redigierter Builder,
fail-closed Verifier, adversariale Tests, Runbook und CI. Ein realer Remote-Run,
Host-/Firewall-/IAM-Aktionen, Wallet, Chain, Mainnet und Produktion sind nicht
Teil dieses Blocks.

Abgeschlossener Produkt-Handover: GH-234/PR #235, code commit `b450740`, exact
main `f146fb2`, ergaenzt den
Development-/Testnet-10-only Light Client um einen separaten one-shot
ThreatHint-v2-Sender fuer ein owner-prepared canonical shared payload. Lokale
Unit- und reale same-host Binary-/QUIC-Tests pruefen strict private inputs,
trusted-network parsing vor Identity/Netzwerk, genau einen Request, redigierte
ACK-Status, Beta/Mainnet-Gates und unveraendertes v1-Verhalten. Exact-main CI
`33272578070`, Security `33272577951` und Pages `33272577407` sind gruen.
Public/multi-host v2, Proof- oder
Approval-Autoritaet, Membership, Model/YARA, Wallet, Chain, Reward, Mainnet,
Deployment und Produktion bleiben offen bzw. ausgeschlossen.
Verbindlicher Status und offene Gates stehen in `CODEX_BRIDGE.md`; laufende
Schritte stehen in `ACTION_LOG.md`.
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
