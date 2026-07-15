# Prometheus Agent Roles

These rules apply to Codex work in this repository. The main GPT-5.6 Sol thread
remains accountable for architecture, security, integration, and final quality.

## Delegation Policy

- Do not spawn a subagent for a trivial task. Delegation is useful when it keeps
  substantial exploration, logs, or an isolated patch out of the main context.
- Use at most one writing subagent at a time. Never assign the same file to two
  agents concurrently.
- Keep nesting at one level. Subagents must not spawn additional agents.
- Give every delegated task explicit files, boundaries, acceptance criteria,
  required checks, and a concise return format.
- Wait for delegated work, inspect its diff, and run the relevant complete test
  suite in the Sol thread before accepting or committing it.

## Model Roles

- **GPT-5.6 Sol (main thread):** architecture, ambiguous or cross-cutting work,
  blockchain/cryptography/contracts, security decisions, CI governance,
  deployment and release decisions, review, integration, and final validation.
- **`spark_worker`:** small isolated patches, targeted searches, mechanical
  documentation consistency, focused unit tests, and quick low-risk iterations.
  It must return uncertain or security-sensitive work to Sol.
- **`terra_analyst`:** read-only repository exploration, larger code/document
  audits, dependency maps, test/log triage, and distilled research findings.

## Prometheus Boundaries

- Read `docs/agent-bridge/CODEX_BRIDGE.md` and relevant `memory/*.md` files before
  product changes. Keep Bridge and Memory current at meaningful milestones.
- Treat existing local diffs and untracked files as foreign work. Never touch,
  stage, inspect, move, or delete `Prometheus-1.png`.
- Never expose or commit secrets, tokens, passwords, private keys, seed phrases,
  wallet/keystore material, or raw signed transactions.
- Preserve the KAS/PROM separation: validators stake KAS; PROM is earned-only.
- Guardian reputation remains canonical on Kaspa L1. Do not add badge, NFT, or
  Kasplex dependencies for reputation.
- Do not introduce an emergency stop, alter `slash()` access control, or change
  the commit-reveal formula without explicit owner approval.
- Use pull requests and required CI checks; do not push directly to `main` or
  bypass branch protection.
