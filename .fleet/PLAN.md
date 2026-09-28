# Prometheus Fleet Plan — canonical delivery plan

Status: canonical (synthesis 2026-09-27; supersedes the 2026-09-27 planning skeleton)
Baseline: exact `origin/main` `32ca5f121855506a5618e3ef1bc803545c425ca1` (2026-09-27).
Fleet docs so far live on this planning branch line: map `7bfd7a6`, inventory
`6bfa60a`/`4d1e518`, synthesis brief `e89e5cb`.
Sources: `docs/architecture/MAP.md` (+ `map.puml`, `main-path.puml`),
`.fleet/reports/plan-arch-map.md`, `.fleet/reports/plan-state-inventory.md`,
project Bridge rules (`docs/agent-bridge/`).
Owner: Codex (orchestration, merge, release gate). Workers: Claude Code (A),
Kimi (B), Grok (C, small bounded scope).

## 0. Truthful current status

- Production: false. No production network operates. PROM emission is not
  implemented; validators stake KAS, never PROM; Guardian reputation is canonical
  Kaspa L1 state only.
- Built: exactly one user-walkable path — ThreatHint v1 submission (hops H1–H8,
  Development/Testnet-10 only) — plus RuleSync, Guardian ballot, the ThreatHint v2
  pipeline, and the keyless silverc-deployer operator (MAP §2–§3).
- Evidence: one confirmed, non-promotable H-001 Testnet-10 canary; one
  operator-attested controlled two-host run (both ends non-authorizing). No
  operated multi-host, no live-model, no production-artifact evidence.
- Blocked externally: six silverc state deployments + oracle `reportMetrics`
  transition (external BIP340 signatures, funded UTXOs), production v2
  relation/keys/ceremony, real model quality.
- Known live defect: fabricated audit dashboard `modules/web/audit/index.html`
  remains on main and public Pages — HIGH public-integrity (#273, R3).
- Open register (verified read-only 2026-09-27): issues #267, #270, #271, #273–
  #280 open; PR #268 draft + CONFLICTING, PR #269 draft + MERGEABLE. Umbrella
  #270 currently shows 0C/8H/15M/20L/5I; corrected totals after R1 are
  0C/7H/15M/20L/5I (PRM-01 invalid, not renumbered).
- Records drift: `memory/TODO.md:288` marks GH-272 `[~]` though PR #281 is merged
  and is current main HEAD; stale BACKLOG baselines; project Bridge closeout
  entries for #269/#270/#281 missing. Hosted Actions runs succeeded 09-19 and
  scheduled 09-21.
- Actions quota: a 2026-10-01 budget reset (USD 0 / stop usage) is **not**
  evidenced for this repository. Verify once, read-only, before relying on it.

## 1. Milestones (ordered gates)

| Gate | Name | Contents | Depends on |
|------|------|----------|------------|
| MS-A | Repository-ready (public-integrity repair first) | Blocks A1–A12 below = register R4, R3, R1, R5a–d, R6, R7, R8, R9, R10 | — |
| MS-B | Owner contract decisions | R11 / #276 decision record + child issues | MS-A started; can run in parallel, blocks MS-C |
| MS-C | Testnet-ready | Contract child fixes/tests, scoped security audit, six Testnet-10 deployments + receipts (MAP M1), oracle transition + successor evidence, two-host evidence, U1 tracking issues | MS-A + MS-B |
| MS-D | Production-ready | MAP M2 (v2 production artifacts/ceremony + crypto review), M3 (privacy-reviewed actionable v2 analysis), M4 (Guardian decentralization, Sybil, L1 attestation), M5 (client production sensing), M6 (PROM emission + governance), full deep audit, Sprint 10B, release hardening | MS-C |

## 2. MS-A next implementation blocks (node, files/interfaces, owner)

Order follows the inventory critical path: A1 → A2 → A3 → A4 → A5–A9 → A10 →
A11 → A12. Public-surface blocks (A2, A3, A10, A11, A12) are strictly sequential
under one writer; the Rust lane (A1, A4, A6, A7, A8) may proceed in parallel.

- **A1 = R4, #267/PR#268.** Node: target endpoint detection gate (GH-258/261 row,
  MAP §3). Files: PR#268's 25 files incl. overlap with claim-verifier scripts.
  Mechanical rebase only, re-run local gates, merge **before** A2 to avoid double
  conflict churn. Owner: Kimi. Codex merges.
- **A2 = R3, #273.** Node: `modules/web`. Files: `modules/web/audit/index.html`,
  `llms.txt`, HTML links, claim-consistency gate. Smallest honest action: remove
  page + links. Owner: Claude (frontend-visual-release-gate).
- **A3 = R1, #271/PR#269.** Node: public audit records (`docs/`). Docs-only:
  rebase; mark PRM-01 invalid (not renumbered); fix PRM-26 "tie accepts"; MD
  span; rustls as separate addendum ID; recompute totals 0C/7H/15M/20L/5I + SHA
  pins; PDF supersession for 3a9556..ff37. Requires Gio/auditor consent first
  (PR is external-auditor authored). Owner: Claude; Codex review.
- **A4 = R5a, #274 PRM-03 (first, Medium, live).** Node: `modules/client`
  runtime-mode gate. Interface: `PROMETHEUS_RUNTIME` fail-closed default; submit
  preflight (`network/p2p.rs`) rejects beta/mainnet before any network activity.
  Failing regression first; fmt/clippy -D warnings/tests. Owner: Kimi.
- **A5 = R5b, PRM-02.** Node: `modules/guardian-node` owner-local membership
  authority. File: `jaeger/guardian_membership_transition.py` — epoch
  monotonicity. pytest Guardian. Owner: Claude.
- **A4H = public honesty handoff, inserted before A5.** Node: public claims +
  `modules/web`. Reconcile README/landing/whitepaper/roadmap/FAQ against current
  code; #282 is the separate A4 runtime fix and #283 remains a separate CI
  semantic-verification task. Owner: Claude; visual gate required.
- **A6 = R5c, PRM-04/05/11.** Node: `modules/client` dev scanner. File:
  `src/security/scanner.rs::YaraScanner` — bounds. Owner: Kimi.
- **A7 = R5d, PRM-06/07/08.** Three serial boundaries: A7a
  `modules/silverc-deployer/src/main.rs::Cli` output collisions (Kimi); A7b
  Guardian v1 verifier/ledger safety; A7c Guardian policy-file descriptor
  reads (Claude). Security review is mandatory; PRM-12 folds in only where a
  touched format can be hardened without widening an interface.
- **A8 = R6, #279 (GH-279, PRM-09).** Node: `modules/guardian-node`
  Compose/dependency boundary + docs; no code-authority change. Decide +
  lock: httpx floor, yara-x 1.4.0, coincurve. pytest + pip reproducibility.
  Owner: Kimi.
- **A9 = R7, #280 (GH-280, PRM-10).** Node: `modules/guardian-node` Compose
  runtime. Files: `docker-compose.yml`, `tests/test_guardian_vllm_compose.py`.
  Needs Gio defaults first (GID 0, tmpfs noexec, loopback vLLM trust); compose
  validation test. Owner: Grok.
- **A10 = R8, #275.** Node: `modules/web` + Pages. Owner decision first: service
  worker repair vs remove; PRM-30 wording only (third-party outage); PRM-33 no
  action. Owner: Claude (visual gate).
- **A11 = R9, #277.** Node: public records (`memory/`, `BACKLOG.md`,
  `robots.txt`, `CLAUDE.md`, project Bridge). One batched docs PR; PRM-34 bug
  bounty = Gio decision. Owner: Claude; small metadata split to Grok.
- **A12 = R10, #278.** Node: `modules/web` frontend system (PRM-43/44/47/48).
  LAST public PR, after A2/A10/A11. Visual gate on 4 viewports. Owner: Claude.
- **DA1 (parallel design, after A1 merge):** GH-258/261 next observe-only slice.
  Node: `modules/threat-hint/src/endpoint_observation.rs` +
  `docs/endpoint-observation-v1.md`. Privacy/threat-model review package +
  bounded local producer *design* only — no sensor, transport, or response.
  Owner: Kimi.

Obsolete/duplicate dispositions (no work): PRM-01 invalid; RUSTSEC-2026-0285
done by #281; PRM-27/33/42/48 informational, close on umbrella #270; closed
#258/#261/#264 tracked forward only via #267. Umbrella #270 stays open until
R3–R10 children close; totals updated after A3.

## 3. Ownership (non-overlapping lanes)

- **Codex:** orchestration, briefs, merges, MS-B decision record with Gio, U1
  tracking issues, final review/integration, release gate, one read-only Actions
  availability check. No product code except explicit handover.
- **Kimi:** A1, A4, A6, A7, A8, DA1 — Rust modules, dependency policy,
  threat-hint boundary design. Never touches public surfaces
  (`index.html`, `llms.txt`, Pages, frontend).
- **Claude:** A2, A3, A5, A10, A11, A12 — public surfaces, Python membership,
  frontend; runs the visual release gate on every public-surface PR. Never
  touches Rust modules.
- **Grok:** A9 compose hardening, small metadata pieces of A11, short focused
  reviews — only explicitly briefed small file sets.

## 4. CI strategy

Before the 2026-10-01 Actions reset:

- Do not assume the quota binds; Codex verifies availability once, read-only.
- `ci.yml` / `security-audit.yml` have no paths filter: every PR event costs a
  full ~7.5 min CI + Security run. Pushes to `agent/*` do not trigger CI.
- All pre-merge gates run locally (fmt, clippy -D warnings, workspace tests,
  pytest Guardian, memory integrity, documentation hygiene).
- Open PRs only at final head; no reruns, no status-only pushes; batch A11 docs
  into one PR; A1 rebase costs exactly one hosted run.
- If the quota proves binding: pre-reset only local gates on A1–A3; merges wait
  for hosted green after the reset.

After 2026-10-01:

- Every merge requires hosted Prometheus CI + Security Audit + Pages green on the
  exact merge commit. Branch protection stays: PR-only, strict up-to-date,
  linear history, resolved conversations, all protected contexts; no admin
  bypass; workers never merge to main.
- Exact-main verification (CI/Security/Pages run IDs + live public markers) is
  recorded per merge, as today.

## 5. Security-audit timing (Cloudflare-origin `security-audit` skill)

Decision: **not now** — the PRM register is 12 days old with fixes pending; a run
now would re-find known items.

1. Scoped `standard` run: after A4–A9 (R5/R6/R7) merge. Scope:
   `modules/client`, `modules/guardian-node`, `modules/guardian-p2p`,
   `modules/silverc-deployer`, `scripts/`, `.github/`. Prior-run baseline: the
   PRM register. Findings feed the #270 umbrella.
2. Full `deep` run incl. contracts: after MS-B children, before any state
   deployment (gate into MS-C closeout).

Both runs require Gio budget approval (plan-level gate).

## 6. Blockers requiring Gio

1. MS-B / #276: seven contract decisions — membership/nullifier, trusted DAA
   time, bond custody, proposal auth + quorum, address binding, cooldown 100800
   vs 7d, `.ss` vs `.sil` (decision session, recorded by Codex).
2. A10 / #275: service worker repair-vs-remove decision.
3. A11 / PRM-34: bug-bounty publication decision.
4. A9 / GH-280: identity/resource defaults (GID 0, tmpfs noexec, loopback vLLM
   trust).
5. A3 / PR#269: consent for edits to the external-auditor-authored PR.
6. Security-audit budget approval (two runs, §5).
7. Actions budget/quota status confirmation (one read-only check).
8. External (non-repo): BIP340 signatures + funded UTXOs for the six deployments
   and the oracle transition; production v2 ceremony participants.

## 7. Explicitly not to build (bound decisions)

- Emergency stop / killswitch; badge/NFT/Kasplex reputation; PROM staking,
  pre-mine, ICO, passive mining rewards.
- Actionable v1 analysis or fabricated indicators from hash-only hints;
  stratum interception / ASIC firmware changes in the miner companion.
- Endpoint response automation (process kill, quarantine, firewall, credential
  rotation, remote commands, deletion, host isolation) — unauthorized.
- Extending legacy `.ss` contracts or the pre-Covenant KRC-20 path; a client
  prover as a second verifier.
- Not yet: actionable v2 analysis (needs M2 + new high-risk ticket), client real
  inference (M5), PROM emission (M6), public multi-host, endpoint
  sensor/transport/response beyond the DA1 design slice, any
  contract/tokenomics/governance change before MS-B decisions, any
  product/public-page code inside planning tasks.

## 8. Definition of Done and stop conditions

- **MS-A DoD:** A1–A12 merged via protected PRs; exact-main CI + Security +
  Pages green after each merge; register items closed or explicitly carried;
  records reconciled (TODO/BACKLOG/Bridge current); no known fabricated public
  claim on main or Pages. **Stop:** any block requires a contract, tokenomics,
  or security-model change → stop, escalate to Gio; any audit finding re-opens
  critical severity → MS-C entry holds.
- **MS-B DoD:** decision record with seven explicit decisions + rationale;
  child issues per contract opened; zero code written in this gate. **Stop:**
  Gio defers a decision → the affected contract child stays blocked, the rest
  proceeds.
- **MS-C DoD:** six deployments with `operator_record` receipts verified by the
  repo scripts; confirmed oracle `reportMetrics` transition with successor
  evidence; attested two-host evidence; scoped-audit findings triaged into the
  register; release-hardening evidence for the exact commit. **Stop:** any
  failed verification, ambiguous node visibility, or unbudgeted audit →
  `ROLLOUT_BLOCKED` stands; no readiness promotion claims.
- **MS-D DoD:** MAP M2–M6 acceptance each met with independent review; full deep
  audit and independent contract/crypto review complete; operated multi-host
  evidence; Gio release decision. **Stop:** whitepaper targets (e.g. < 60 s
  lifecycle) remain unproven → stay unclaimed; any privacy review failure on
  M3/M5 blocks that milestone.

## 9. Standing constraints

- One writer per surface; lanes per §3. Workers never merge to main; Codex holds
  the release gate; no force-push.
- Existing local diffs/untracked files in the primary checkout remain foreign
  and untouched; never touch `Prometheus-1.png`.
- Next implementation begins only from a named architecture node and an
  approved brief; `docs/architecture/MAP.md` is updated when modules, hops, or
  status change.
- KAS/PROM separation holds; Guardian reputation stays canonical on Kaspa L1.
- No secrets, tokens, keys, wallet data, or operational topology in fleet files.
  Testnet-only keys for development.

## 10. Milestone progress

### 2026-09-28 — A1 locally integrated

- PR #268 was mechanically ported from `5960f1b` onto the current planning
  baseline without mutating the original branch.
- The additive Security Audit workflow step is retained: it changes no trigger,
  permission, secret, deployment, or required-check governance and keeps the
  public Security-CI claim truthful.
- Focused fallback review passed; Kimi and Grok were unavailable, so fresh
  Claude workers produced the candidate and bounded independent review.
- Integration gates pass: privacy verifier, 37 privacy tests, public claims,
  69 claim tests, documentation hygiene, Memory, status, Autodidactic, YAML,
  visual assertions/screenshots, and diff check.
- State: `A1 LOCAL VERIFIED / HOSTED PR CHECKS PENDING / PRODUCTION FALSE`.

### 2026-09-28 — A2 locally integrated

- Removed the fabricated public audit dashboard and all public links, sitemap
  entries, architecture pointers, and developer-guide references to it.
- Kimi completed the bounded implementation after Claude fallback; no second
  implementation was performed.
- Integration gates pass: 13-surface claim verifier, 76 claim tests,
  documentation hygiene plus 11 tests, Memory, status plus 7 tests,
  Autodidactic plus 6 tests, targeted absence checks, and diff check.
- Responsive assertions pass at 1440x1000, 1180x820, 820x1180, and 390x844:
  no page overflow and no audit-dashboard link. Existing contrast and touch
  target debt remains assigned to A12 and is not represented as fixed here.
- State: `A2 LOCAL VERIFIED / HOSTED PR CHECKS PENDING / PRODUCTION FALSE`.

### 2026-09-28 — A3 locally integrated

- Imported and corrected the five public reports plus register README from
  draft PR #269 without changing finding IDs or product behavior.
- PRM-01 is withdrawn as invalid, PRM-26 states that threshold ties are
  accepted, and the rustls advisory is separated as addendum PRM-A01.
- Corrected totals are `0C / 7H / 15M / 20L / 5I`; all five report SHA-256
  pins match. The old PDF digest `3a9556…ff37` is explicitly superseded and no
  replacement PDF digest is invented.
- Claude completed the bounded retry after the first zero-diff Fleet failure;
  Kimi was token-limited. No duplicate implementation or routine review ran.
- Integration gates pass: documentation hygiene plus 11 tests, 13-surface
  claim verifier plus 76 tests, Memory, project status plus 7 tests, targeted
  correction/hash checks, and diff check.
- State: `A3 LOCAL VERIFIED / PR #269 UPDATE + HOSTED CI PENDING / PRODUCTION FALSE`.

### 2026-09-28 — A4 locally integrated

- PRM-03 is confirmed and fixed at `modules/client` MAP hop H1. ThreatHint v1
  and v2 preflight/submit now require an explicit `PROMETHEUS_RUNTIME=development`
  before hint, identity, or transport activity.
- Missing, empty, malformed, beta, and mainnet process modes fail closed; the
  validated mode must also agree. No wire format, retry, CLI flag, or new path
  was introduced.
- Claude delivered the bounded retry. Grok review fell back to a fresh Claude
  reviewer (`verdict: ok`); Codex therefore performed the focused security diff
  review before integration and found no remaining issue.
- Gates pass: `cargo fmt --all -- --check`, 4 runtime tests, real-binary H1
  loopback regression, complete client tests, client Clippy with `-D warnings`,
  and diff check.
- State: `A4 LOCAL VERIFIED / HOSTED CI PENDING / PRODUCTION FALSE`.

### 2026-09-28 — A4H paused after three zero-diff worker failures

- The external README honesty handoff and evidence were catalogued; temporary
  Fleet files were checksum-backed up outside `/private/tmp`.
- One full and two reduced Claude tasks produced no report and no diff. Kimi
  and Grok probes reported `token_limited`; Solo mode is not justified because
  Claude remains generally available.
- No public file was changed. Issues #282 and #283 remain separate; #282 maps
  to locally verified A4 and #283 remains open CI work.
- A4H stays a public-activity gate and resumes with a restored independent
  worker. Safe non-public A5 work may continue without weakening this gate.
- State: `A4H OPEN / WORKER DELIVERY BLOCKED / PRODUCTION FALSE`.

### 2026-09-28 — A5 locally verified; PRM-02 invalid

- Re-verification proved that strict parser monotonicity plus durable current
  epoch/digest binding already rejects equal, lower, stale, bootstrap rollback,
  and skipped authority epochs. Production code was not changed.
- Added committed rollback/restart/no-mutation regressions. Focused membership
  tests pass `58/58`; the complete Guardian suite passes `1393`, with `4`
  intentional skips, outside the filesystem sandbox required by socket/mode tests.
- Corrected the public audit without renumbering: PRM-02 is withdrawn, totals
  are `0C/7H/14M/20L/5I`, and the full-scope SHA-256 pin is
  `aff6382e741278e1a83cc6d0ce4188549453354f2bdbecd364ad6621e6138417`.
- Documentation hygiene (11 tests), 13-surface verifier (76 tests), hash pins,
  security diff review, and diff check pass.
- State: `A5 LOCAL VERIFIED / HOSTED CI PENDING / PRODUCTION FALSE`.

### 2026-09-28 — A6 locally verified

- PRM-04 is fixed fail-closed: the development scanner accepts only its
  explicit any-of subset and rejects unsupported YARA syntax instead of
  changing semantics.
- PRM-05 is fixed with capped `limit + 1` reads for scanner and detector file
  APIs; empty and oversized input fail before unbounded allocation.
- PRM-11 is fixed in the development KRC20 cache with validated rule identity,
  canonical CID and consensus, 256-entry capacity, deterministic duplicate
  handling, and no mutation on rejection.
- Claude implemented three serial slices; Codex performed the security diffs
  and combined verification. Initial A6c linking hit a full disk; only
  regenerable A6a/A6b Cargo targets were cleaned before successful reruns.
- Gates pass: format, focused scanner/file/cache regressions, complete client
  suite `347 passed, 2 ignored`, client Clippy with `-D warnings`, and diff
  check. No network, deploy, wallet, chain, contract, or production action.
- State: `A6 LOCAL VERIFIED / HOSTED CI PENDING / PRODUCTION FALSE`.

### 2026-09-28 — A7 started; upstream reconciliation recorded

- JEV routing choice was `single_claude_brief`; deterministic architecture
  boundaries override it because PRM-06/07/08 span Rust deployer and Python
  Guardian hops. A7 therefore uses three serial, non-overlapping briefs.
- Official upstream has moved to Rusty Kaspa v2.1.0 and Silverscript v1.0.0;
  this repo still builds Rusty Kaspa v2.0.1. Version reconciliation is a
  separate pre-rollout gate, not bundled into the A7 security fixes.
- State: `A7 IN PROGRESS / PRODUCTION FALSE`.

### 2026-09-28 — A7 locally verified

- PRM-06 now rejects deployer import/output collisions before preflight,
  prepare, signature verification, broadcast, or observation writes. Broadcast
  also protects its derived intent journal. The residual pathname race after
  validation remains explicit and is not represented as eliminated.
- PRM-07 now binds the Guardian v1 verifier to a required, canonical SHA-256
  configured through the exact TOML schema, rechecks the executable before
  every spawn, hardens process-group cleanup, and opens the replay ledger with
  no-follow and exact owner-only mode checks. A7b/A7b2 partial reports are
  completed by A7b3 service wiring; no TOFU, environment fallback, or default
  digest was introduced.
- PRM-08 now reads Guardian service and v2 policy configuration once through a
  no-follow descriptor with bounded reads plus pre/post identity checks. No
  pathname reopen remains at these two boundaries.
- Kimi received A7a but the dispatcher fell back to Claude. Claude implemented
  the non-overlapping slices; Codex reviewed each security diff and ran the
  combined integration gate. No duplicate implementation was performed.
- PASS: Rust format; silverc-deployer `50` unit and `6` collision integration
  tests; silverc-deployer Clippy with `-D warnings`; Guardian `1426 passed, 4
  skipped`; Black; Ruff; CI-equivalent full-package Pylint `9.86/10` with
  `--fail-under=7.0`; and diff check. Sandbox-only Unix-socket and mode failures
  were reproduced and then excluded by the unrestricted canonical test run.
- No network, deploy, wallet, chain, contract, migration, or production action.
  Rusty Kaspa v2.1.0/Silverscript v1.0.0 reconciliation and real public
  multi-host under-60-second evidence remain separate rollout gates.
- State: `A7 LOCAL VERIFIED / HOSTED CI PENDING / PRODUCTION FALSE`.

### 2026-09-28 — A8 compatibility and pinning gate started

- Boundary: build/toolchain trust before `contracts/silverc` and
  `silverc-deployer`; no runtime, contract, proof, or security-fix scope.
- A8a assigns Kimi a read-only exact-pin and compatibility inventory. A8b will
  be written only from that report, with one writer and a rollback point.
- JEV routing produced no value after one corrected retry; deterministic serial
  inventory then implementation therefore governs.
- State: `A8 INVENTORY IN PROGRESS / PRODUCTION FALSE`.
