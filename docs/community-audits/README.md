# Community Audits — Collateral Web3 Open Audits

External audit series of the Prometheus project, commissioned by the repository
owner and published here with his explicit authorization (public series like
IFR/Ekklesia/Stealth). **Report-only**: no audited code was changed; no chain
actions; no binaries executed against any network; no secret files read;
`Prometheus-1.png` untouched (repo AGENTS.md). Contract recommendations respect
the repo boundaries — no emergency-stop proposal, no `slash()` ACL redesign, no
commit-reveal formula change; all are framed as owner decisions.

- **Audit date:** 2026-09-15
- **Baseline:** `main` @ `8b5da58a34172062cf644db52ba459385d151562`
- **Register:** PRM-01 … PRM-48 — **0 Critical / 8 High / 15 Medium / 20 Low / 5 Informational**
- **Severity context:** only the stateless H-001 canary verifier is on-chain
  (Testnet-10, no state, no value). All contract-level Highs are design-phase
  findings rated "if deployed as written" — nothing is live-exploitable today.
- **Prior baseline:** internal public claim audit 2026-08-14
  (`docs/claim-audit-2026-08-14.md`) — its corrections independently
  spot-verified as landed on all five main pages (see content report, PRM-42).
- **Finding tracker:** umbrella issue (see issue list) with one checkbox per finding.

## Reports

| # | Report | Register | Severity (C/H/M/L/I) | SHA-256 |
|---|--------|----------|----------------------|---------|
| 1 | [Full-scope security](prm-full-scope-audit-2026-09-15.md) | PRM-01…12 | 0/1/2/8/1 | `7904d778d55c862f932e3975c212011a69c892002ace28d52f456586943c660e` |
| 2 | [Cryptography & contracts](prm-crypto-contracts-audit-2026-09-15.md) | PRM-13…27 | 0/6/6/2/1 | `7e13fec91f2029d0edd874064c1ef1ead62c8eac6fa7bc77b7c2a31a60792ece` |
| 3 | [Integration & surfaces](prm-integration-surfaces-audit-2026-09-15.md) | PRM-28…33 | 0/1/2/2/1 | `70be1c028367243f20d8eba5f10655273a8a6faf63db3873e1369e9f89c33c3b` |
| 4 | [Content & coherence](prm-content-coherence-audit-2026-09-15.md) | PRM-34…42 | 0/0/3/5/1 | `58f19ea5a477af048dc93eb09c716fd66b3256b79b49b9ffae889b33cddc23e2` |
| 5 | [AI-readiness & landing quality](prm-ai-readiness-landing-audit-2026-09-15.md) | PRM-43…48 | 0/0/2/3/1 | `2ba3e57b814e68f75c2021af899ecf0216a5fe83154c4f314eea9b6016bd0813` |

## Headline findings

- **PRM-01 (High, live code):** guardian-node SQLite `_raise_operational_error`
  falls through for non-lock errors (FULL/IOERR/CORRUPT/READONLY…) → false
  success receipts at the replay boundary; sibling module has the terminal
  raise. Two-line fix, highest priority of this series
  (`jaeger/observable_approval_consumption.py:2456-2462`).
- **PRM-28 (High, live surface):** the site-wide linked "Open Audit Dashboard"
  shows fabricated validators/rules/PROM grants and "All data verifiable
  on-chain" with zero JavaScript — excluded from all 13 surfaces of the project's
  own claim-consistency checker (`modules/web/audit/index.html`).
- **PRM-13…18 (High, pre-deployment design):** `.sil` dead-state permanent fund
  lock; membership-less replay-able covenant voting; caller-supplied time
  everywhere; `.ss` bond paid out but never collected; unauthenticated
  `submitProposal` with victim-pubkey griefing; 1-of-N quorum acceptance.
- **PRM-35 (Medium):** `COOLDOWN_BLOCKS = 100800 // ~7 days at 10 BPS` is off by
  60× (≈2.8 hours) — propagated to whitepaper and validator guide.
- **PRM-43 (Medium):** the user-reported "uncoordinated landing" has an
  objective cause: duplicated CSS rule blocks override text to #333 on #050505
  (1.61:1 contrast) across all pages.

## Verified strengths (selection)

Zero `unsafe` workspace-wide; 13 panic sites all input-unreachable; keyless
deployer with full local re-execution before broadcast; BIP340 via libsecp256k1
with dual-signature rotation; commit-reveal formula byte-exact across
Rust/Python/.sil (vectors independently recomputed); Groth16 v2 canonical
binding; zero third-party scripts on the site; evidence JSONs honest and
leak-free; CI green on baseline with least-privilege permissions; the internal
claim-audit discipline is genuine and its corrections landed.
