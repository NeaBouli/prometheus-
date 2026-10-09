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
- **Register:** PRM-01 … PRM-48 — **0 Critical / 7 High / 14 Medium / 20 Low / 5 Informational**
  (corrected 2026-09-28; PRM-01 and PRM-02 invalid and excluded, IDs not renumbered;
  addendum PRM-A01 is tracked outside these totals — see [Corrections](#corrections-2026-09-28))
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
| 1 | [Full-scope security](prm-full-scope-audit-2026-09-15.md) | PRM-01…12 | 0/0/1/8/1 | `aff6382e741278e1a83cc6d0ce4188549453354f2bdbecd364ad6621e6138417` |
| 2 | [Cryptography & contracts](prm-crypto-contracts-audit-2026-09-15.md) | PRM-13…27 | 0/6/6/2/1 | `c833b690552bab9121bc17a8c1e9cfbec06f9aaa583bb0670cc72f82aa34c4ce` |
| 3 | [Integration & surfaces](prm-integration-surfaces-audit-2026-09-15.md) | PRM-28…33 | 0/1/2/2/1 | `70be1c028367243f20d8eba5f10655273a8a6faf63db3873e1369e9f89c33c3b` |
| 4 | [Content & coherence](prm-content-coherence-audit-2026-09-15.md) | PRM-34…42 | 0/0/3/5/1 | `c430c46103b2e5f7806cdf7f8496ed779855e17f48df083e54956af0853f5d87` |
| 5 | [AI-readiness & landing quality](prm-ai-readiness-landing-audit-2026-09-15.md) | PRM-43…48 | 0/0/2/3/1 | `2ba3e57b814e68f75c2021af899ecf0216a5fe83154c4f314eea9b6016bd0813` |

SHA-256 pins above are recomputed over the corrected files (2026-09-28).
Integration and AI-readiness reports are unchanged, so their pins are unchanged.

## Headline findings

- **PRM-01 (invalid, withdrawn 2026-09-28):** the reported SQLite
  `_raise_operational_error` fall-through does not exist at the baseline; the
  helper ends with a terminal raise (`:2463`). Kept as a visible invalid ID,
  not renumbered, excluded from all totals.
- **PRM-02 (invalid, withdrawn 2026-09-28):** strict transition parsing and
  durable current-state binding already reject equal, lower, stale, and skipped
  membership/authority epochs; regression tests confirm no mutation.
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

## Corrections 2026-09-28

Record corrections only; no finding was added, re-rated or renumbered except
as listed.

| Item | Correction |
|------|------------|
| PRM-01 | **Invalid.** Withdrawn after re-verification at baseline `8b5da58a`; original text retained in the full-scope report under a withdrawal notice. High total 8 → 7. |
| PRM-02 | **Invalid.** Strict parser monotonicity plus durable current-epoch/digest binding reject the claimed bootstrap rollback; original text retained under a withdrawal notice. Medium total 15 → 14. |
| PRM-26 | Wording corrected: `VALIDATOR_QUORUM = 6700` is 67%, not 2/3, and the `>=` comparison accepts ties at the threshold. Severity unchanged. |
| PRM-36 | Malformed Markdown code/emphasis span repaired. Wording unchanged. |
| PRM-A01 | **Addendum ID** for the `rustls` dependency advisory `RUSTSEC-2026-0285`. Not part of the 2026-09-15 PRM-01…48 register; tracked separately and excluded from the totals above. Status: resolved on `main` by GH-272 (PR #281, lockfile-only `rustls`/`rustls-webpki`/`quinn` update); `cargo audit` reports the advisory absent. |

### Superseded pins

The pins of the three corrected reports as first published are superseded by
the table above:

| Report | Superseded SHA-256 |
|--------|--------------------|
| Full-scope security | `7904d778d55c862f932e3975c212011a69c892002ace28d52f456586943c660e` |
| Full-scope security (before PRM-02 correction) | `1eaa77446d745967daf92bd7e7c2f301b5ec2df099110b8194143e5eebdbc4a1` |
| Cryptography & contracts | `7e13fec91f2029d0edd874064c1ef1ead62c8eac6fa7bc77b7c2a31a60792ece` |
| Content & coherence | `58f19ea5a477af048dc93eb09c716fd66b3256b79b49b9ffae889b33cddc23e2` |

The PDF edition of this series with the SHA-256 digest beginning `3a9556` and
ending `ff37` is **superseded**: it carries the uncorrected register (8 High,
15 Medium; PRM-01 and PRM-02 valid). No corrected PDF is published in this repository, so no
replacement PDF digest is recorded. The Markdown reports and the pins above
are authoritative.

## Maintainer Status Overlay (2026-10-10)

The reports above describe their dated audit baseline, not current live
vulnerabilities or release readiness. The separate
[48-ID maintainer reconciliation](maintainer-status-2026-10-10.md) maps
withdrawals, exact merged repairs, partial items, external uncertainty and
remaining pre-deployment gates. It preserves the corrected report bytes/pins
and superseded PDF history; issue #270 remains open. No full security acceptance
or production claim follows from either the historical reports or the overlay.
