# Action Log

## 2026-07-08

- Verified working tree after push: branch `main` tracks `origin/main`; only untracked local artifacts are `.claude/` and `Prometheus-1.png`.
- Confirmed current local/remote HEAD is `eeb4808` after the post-Toccata bridge/docs update.
- Reconciled stale bridge/backlog/checkpoint status entries that still referenced `467ca03` or April startflow data.
- Updated `memory/STATUS.md` to mark GitHub Actions CI/CD as accepted for the green `eeb4808` CI, Security Audit, and Pages runs.
- No product code changed in this reconciliation pass.

## 2026-07-07

- Codex onboarding check completed at 20:19 EEST: read bridge, cooperation rules, CLAUDE.md, BACKLOG.md, and required memory files.
- Verified current repo state: branch `main`, HEAD `467ca03`, local uncommitted memory/bridge/docs assets present.
- Verified direct Sandbox access via `ssh sandbox` using BatchMode: host `Sandbox`, user `root`.
- Completed read-only repository audit and documented findings in `CODEX_FINDINGS.md`.
- Verified checks: `cargo fmt --all --check`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace`, Guardian pytest via temporary `/tmp` venv, memory integrity, and remote HEAD alignment.
- Researched Kaspa Toccata status from current public sources; updated public docs/pages and memory/backlog from stale May 5 launch wording to post-Toccata ssc/H-001 verification status.
- Checked direct Sandbox PATH for `kaspad` and `ssc`; neither was found there, so Sprint 9 still needs local tooling installation/verification.
- Replaced stale current-status wording that said Testnet-12 does not exist with a legacy Testnet-10 baseline plus TN12/Toccata tooling verification requirement.
- Added H-001 Rust guardrail: canonical 17-byte commit-reveal preimage builder plus known hex vectors for normal, zero, endian-visible, and `u64::MAX` cases.
- Updated `ValidatorStaking.ss` comments to document the same canonical H-001 byte preimage without changing contract logic.
- Pinned Rusty-Kaspa workspace dependencies to tag `v2.0.1` and refreshed `Cargo.lock`; local `cargo audit` no longer reports vulnerabilities.
- Re-enabled GitHub Security Audit workflow and changed dependency audits from best-effort `|| true` commands to failing gates.
- Added CI stale public-status check to prevent reintroducing old May 5 launch/Testnet-12 wording.
- Verified after implementation: `cargo fmt --all --check`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace`, `cargo audit`, Guardian Black/Pylint/pytest, `pip-audit`, stale public-status shell check, and memory integrity.
- Added Rust client runtime gate via `PROMETHEUS_RUNTIME`: development remains stub-capable; beta/mainnet/production reject ZK, Phi-3 fallback/heuristic, KRC-20 cache, and Fed-DART placeholder stubs.
- Verified runtime gate with `cargo fmt --all --check`, `cargo test -p prometheus-client`, and `cargo clippy --workspace -- -D warnings`.
- Added `CODEX_BRIDGE.md` as the central Codex handover/start file.
- Documented direct Sandbox SSH access via local alias `ssh sandbox`.
- Consolidated Prometheus project identity, workflow logic, audit blockers, open issues, and Reputation Badge decision.
- Explicitly excluded plaintext passwords, private keys, tokens, and other secrets from bridge documentation.

## 2026-05-08
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
