# Prometheus — agent instructions (Claude Code)

Project-specific guidance for Claude Code in this repository. The binding
repository rules for all agents are in [`AGENTS.md`](AGENTS.md); this file does
not relax them. (This replaces a generic security-audit prompt template that
contained no project guidance — audit PRM-41.)

## What this repository is

A development-stage protocol targeting decentralized, AI-assisted threat
intelligence on Kaspa. No production Prometheus network operates. The repository
contains tested development foundations, one confirmed non-promotable H-001
Testnet-10 canary, and rollout gates that remain open. Current status:
`README.md` (Project Status), `docs/roadmap.md`, `memory/STATUS.md`; delivery
plan: `.fleet/PLAN.md`; architecture map: `docs/architecture/MAP.md`.

## Layout

- Rust workspace (`Cargo.toml`): `modules/client` (Light Client binary
  `prometheus-client`), `modules/validator-node` (library only, no binary),
  `modules/guardian-p2p`, `modules/threat-hint`, `modules/threat-proof`,
  `modules/silverc-deployer` (keyless operator; never takes a private key).
- Python Guardian: `modules/guardian-node` (`jaeger/`, `tests/`); install only
  via `requirements-lock.txt` (see `docs/dependency-policy.md`).
- Contracts: current-silverc fixtures `modules/contracts/silverc/*.sil`; legacy
  `modules/contracts/*.ss` are historical and must not be extended.
- Public site: `index.html`, `roadmap.html`, `faq.html`, `whitepaper.html`,
  `guardian-economics.html`, `llms.txt`, `sitemap.xml`, `robots.txt`.
- Fleet coordination: `.fleet/` (plan, briefs, reports); project bridge log:
  `docs/agent-bridge/ACTION_LOG.md`.

## Invariants (never change without an explicit owner decision)

- KAS/PROM separation: validators stake KAS, never PROM; PROM is earned-only and
  its minting/emission is not implemented.
- Guardian reputation is canonical Kaspa L1 state, not a token, badge, or NFT.
- No emergency stop/killswitch; `slash()` access control unchanged.
- Toolchain pins (`docs/architecture/toolchain-pins.json`), threat-proof
  identity pins, H-001 evidence under `docs/evidence/`, and the compiled
  contract expectation (`modules/contracts/silverc/expected-compiled-artifacts.json`)
  change only in dedicated, reviewed changes.
- No endpoint response automation; no actionable v1 analysis from hash-only hints.
- Public claims must distinguish implemented / tested / Testnet / target. Never
  claim production, decentralization, model quality, or the under-60-second
  lifecycle as achieved.

## Working rules

- Never touch secrets, keys, wallets, or `Prometheus-1.png`; treat foreign local
  diffs as untouchable. No deployment, broadcast, or Mainnet action.
- Rust: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace --locked`; no `unwrap()` in production code.
- Python: type hints, Black on the CI paths, Pylint, the full Guardian suite
  (`cd modules/guardian-node && PYTHONPATH=. python -m pytest tests/`).
- Public-text changes: `scripts/verify_public_claim_consistency.py`,
  `scripts/check_public_documentation_hygiene.py`,
  `scripts/verify_project_status_consistency.py`,
  `scripts/check_memory_integrity.py` and their tests; visible HTML changes
  additionally need the frontend visual release gate.
- Record each completed task in `docs/agent-bridge/ACTION_LOG.md` and, in fleet
  mode, in `.fleet/PLAN.md` plus a report under `.fleet/reports/`.
- Workers never merge to `main`; merges go through protected PRs and the
  orchestrator's release gate.
