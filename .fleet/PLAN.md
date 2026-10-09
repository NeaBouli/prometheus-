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

- A8a produced no report or diff. Canonical probes: Kimi `token_limited`,
  Claude `available`, Grok `available`. A8a2 assigns the same inventory to
  Claude; Grok remains unused because the scope exceeds its role boundary.

- A8a2 also produced no report or diff. The broad inventory is replaced, not
  repeated, by serial bounded slices: A8a3 SilverC/CI, then A8a4 Cargo/Kaspa.

- A8a3 is independently source-verified: medium fail-open SilverC pinning debt
  confirmed; H-001 evidence stays immutable. A8a4 now maps Cargo/Kaspa only.

- A8a4 independently confirms the Cargo source-policy gap and immutable proof
  identity pins. A8b starts SilverC hardening with the active pin unchanged.

- A8b returned no report/diff. It is reduced to A8b1 checkout/pin enforcement,
  followed serially by A8b2 manifest/rebuild/locked-Cargo/CI wiring.

- A8b1 integrated with 26 focused passes. Codex review requires A8b1r to reject
  a symlink checkout path before A8b1 can close.

- A8b1r closes the review finding; A8b1 now passes 27 focused tests, Ruff, and
  Mypy. A8b2 starts manifest/rebuild/locked-Cargo/CI enforcement.

- A8b2 integrated, but Codex review rejects incremental default-target reuse.
  A8b2r must build and execute from a fresh isolated target directory.

- A8b2r closes default-target reuse with 42 focused passes. A8c starts the
  machine-readable Cargo/SilverScript/immutable-proof pin policy and CI gate.

- A8c integrated with 45 focused tests, but Codex review requires A8c1 to bind
  the same immutable relation identity in the Python Guardian parser.

### 2026-09-28 — A8 compatibility and pinning gate locally verified

- A8 now enforces one machine-readable policy for the active Rusty Kaspa
  dependency graph, SilverScript compiler revision, release-manifest compiler
  identity, and immutable Rust/Python threat-proof identity. Direct dependency
  drift, split lock graphs, tags/branches in place of the exact SilverScript
  revision, dirty or symlinked compiler checkouts, and reusable default build
  targets fail closed.
- Active pins remain intentionally unchanged: Rusty Kaspa
  `v2.0.1@cfafeb4c093fa37a303f1b9f19c58f986b870ce3` and SilverScript
  `d25bd3427a093c17327ca3d6b9e1aa5f7688c863`. Rusty Kaspa v2.1.0 and
  SilverScript v1.0.0 are observed candidates only; no upgrade was performed.
- Kimi was canonically `token_limited`. Claude delivered bounded serial slices;
  Codex integrated them and closed three security-review findings without
  duplicating accepted worker work.
- PASS: 55 toolchain-policy tests; 42 SilverC pin/build tests; Ruff; strict
  Mypy; workflow YAML parse; locked offline Cargo tree; 102 Rust tests plus 2
  compile-fail doc-tests; 55 pinned upstream SilverC tests; seven-artifact
  release build; isolated full-profile preflight; H-001 canary-profile
  regression; 7 status-consistency tests; diff check.
- Local `actionlint` and Black were unavailable. The workflow was structurally
  parsed, and its existing Black gate does not target the changed A8 scripts.
  Hosted CI remains the authoritative remote workflow result.
- No deployment, broadcast, wallet, chain, contract, proof artifact, migration,
  secret, or production action. The under-60-second lifecycle remains an
  unproven public multi-host target.
- State: `A8 LOCAL VERIFIED / HOSTED CI PENDING / PRODUCTION FALSE`.

### 2026-09-28 — A8 hosted verification green; PR opened

- PR `#284` opened from the integration branch at `e0f96c6`. The first hosted
  verification completed successfully: Toolchain Pin Policy, Rust Workspace,
  Rust Performance, Current Silverc Runtime + Artifact Smoke, Python Guardian,
  HTML Pages, Memory Integrity, Silverscript Contracts, Secret Detection,
  Dependency Audit, and Security Summary all passed.
- Hosted runs: Prometheus CI `36443057946`; Security Audit `36443057571`.
  CodeRabbit skipped review because the accumulated milestone PR contains 132
  files; this is not recorded as an independent review. Codex's required
  security review and local integration verification remain the review basis.
- State: `A8 VERIFIED / PR #284 OPEN / REVIEW REQUIRED / PRODUCTION FALSE`.

### 2026-09-30 — Claude stand-in starts (Codex token-limited)

- Claude Code continues this thread per `codex-standin` on
  `agent/claude/prometheus-standin-20260930` (stacked on `60ee6db`); handover
  `.fleet/HANDOVER-CLAUDE-20260930.md`. No merge, release gate, or pinned-contract
  change by the stand-in.
- A8u1 (upgrade inventory) closed: Rusty Kaspa v2.1.0 + SilverScript v1.0.0
  cannot form one lock graph yet (SilverScript pins v2.0.1 resp. untagged
  `a41a333b`); only `silverc-deployer` breaks on v2.1.0 and its signing-request
  schema binds `toccata_activation_daa_score`. Active pins stay unchanged;
  A8u2 waits for an upstream SilverScript release on a rusty-kaspa tag.
- PLAN's original A8 content (R6, GH-279, PRM-09) is still open and is next.
- State: `A8u1 DONE / UPGRADE BLOCKED UPSTREAM / PRODUCTION FALSE`.

### 2026-09-30 — GH-279 / PRM-09 locally verified (Claude stand-in)

- Guardian Python dependencies are exact pins plus a generated, universal,
  sha256 hash lock for Python 3.11; CI installs wheels-only with
  `--require-hashes` and runs the new offline gate
  `scripts/verify_guardian_python_deps.py` (binds yara-x to the runtime pin).
  Public policy: `docs/dependency-policy.md`. yara-x 1.4.0 kept deliberately.
- PASS: Guardian 1426 passed / 4 skipped in the locked 3.11 venv; Black,
  Pylint 9.86; pip-audit clean; 18 gate tests; 374 script tests; ruff/mypy.
- Review owed to Codex (supply-chain/CI surface). Hosted CI pending.
- State: `GH-279 LOCAL VERIFIED / REVIEW OWED / PRODUCTION FALSE`.

### 2026-09-30 — GH-283 compiled-contract semantic gate locally verified (Claude stand-in)

- CI now compares the pinned-silverc smoke manifest with a reviewed compiled
  expectation (script bytes, ABI, state layout, ctor args, compiler pin); a
  negative regression proves two behavior-changing mutants that keep every
  linted literal are rejected. Boundary documented in the silverc README.
- Archive SHA-256 `4989f076…` reproduces the August H-001 evidence value.
- Review owed to Codex. State: `GH-283 LOCAL VERIFIED / PRODUCTION FALSE`.

### 2026-09-30 — A4H public honesty closed on the stand-in branch (Claude)

- Re-verified the 2026-09-28 findings; most were already fixed. Corrected the
  remaining confirmed items: non-working validator run command, present-tense
  KAS staking/slashing, Sprint-1 legacy contract label, ACCEPTED label meaning.
  No HTML change (visual gate not triggered). Claim/status/hygiene gates pass.
- Review owed to Codex before any public activity. State: `A4H LOCAL VERIFIED`.

### 2026-09-30 — A11 / GH-277 public records reconciled (Claude stand-in)

- PRM-34 bounty labelled planned/unfunded (funding = Gio), PRM-36 supersede
  banners + GH-272 closed in TODO, PRM-37 guides, PRM-38/39 landing and
  guardian-economics wording with 4-viewport visual gate, PRM-40 paths,
  PRM-41 project-specific CLAUDE.md, PRM-46 robots.txt (security.txt
  intentionally not added on a project page).
- State: `A11 LOCAL VERIFIED (PARTIAL: PRM-34 DECISION) / PRODUCTION FALSE`.

### 2026-09-30 — A12a contrast (PRM-43) locally verified (Claude stand-in)

- index.html duplicate-selector dead code removed (pixel-identical), text
  tokens raised to WCAG AA on all five pages, unstyled links fixed; rendered
  audit 796 → 0 failing text nodes; new CI gate `verify_site_css.py`.
- State: `A12a LOCAL VERIFIED / POST-DEPLOY RECHECK OWED`.

### 2026-09-30 — A12b accessibility/validity locally verified (Claude stand-in)

- noopener on external links, logo href, skip link to focusable main,
  reduced-motion and no-JS fallbacks. State: `A12b LOCAL VERIFIED`.

### 2026-09-30 — A12d image weights locally verified (Claude stand-in)

- Display-sized logo/coin variants; index images ≈3.1 MB → ≈208 KB.
  PRM-35 cooldown text on the token card noted for #276. State: `A12d LOCAL VERIFIED`.

### 2026-09-30 — Owner decision PRM-34: no bug bounty (Gio)

- Gio: PROM would first have to be minted and there is no pool, so a PROM
  bounty is not a sound approach — remove it. SECURITY.md now states there is
  no bug bounty program (no PROM reward offered or planned); disclosure via
  GitHub Security Advisories unchanged. A11 PRM-34 is thereby closed.

### 2026-09-30 — Gio delegates technical owner decisions to Claude

- Gio: "entscheide du, ich kenne mich hier nicht aus" (service worker, cooldown,
  container defaults). Decisions and rationale below; review owed to Codex.
- A10/#275 DECIDED remove: service worker never installed (root paths 404);
  cleanup worker + registrations removed; dead GSC meta removed; explorer
  outage wording. Report `.fleet/reports/a10-service-worker.md`.
- A9/#280 DECIDED: 2000:2000, CPU caps 16/64, /tmp stays exec (JIT), loopback
  vLLM documented as single-operator trust boundary. Report
  `.fleet/reports/a9-guardian-compose.md`.
- PRM-35 / #276 cooldown DECIDED: 7 days (6,048,000 blocks), because the 1-day
  voting period must settle before exit. Implementation deferred to a reviewed
  "contract bundle v2" (the deployer pins the H-001 bundle manifest); public
  text states decided target vs current fixture. Report
  `.fleet/reports/prm35-cooldown-decision.md`.

### 2026-09-30 — A12c shared stylesheet (PRM-44) locally verified (Claude stand-in)

- `assets/site.css` holds tokens + shared chrome; all pages pixel-identical
  before/after (incl. menu and focus states); gate checks the combined
  cascade. GH-278 (A12a–d) is complete on the stand-in branch.
- State: `A12 LOCAL VERIFIED / POST-DEPLOY RECHECK OWED / PRODUCTION FALSE`.

### 2026-09-30 — DA1 endpoint producer design delivered (Claude stand-in)

- `docs/endpoint-producer-design-v1.md`: design-only resource-utilization
  producer candidate mapped to all GH-267 requirements; no code, no status
  change. Next: independent privacy review + owner approval before any brief.

### 2026-09-30 — Stand-in branch hosted verification green

- `workflow_dispatch` on `agent/claude/prometheus-standin-20260930` at
  `bff7fc1`: Prometheus CI `36698349293` success (Memory Integrity,
  Silverscript Contracts, Python Guardian, HTML Pages, Toolchain Pin Policy,
  Current Silverc Runtime + Artifact Smoke, Rust Workspace, Rust Performance);
  Security Audit `36698357152` success (Dependency Audit, Secret Detection,
  Security Summary). This proves GH-279 wheels-only hash install on Ubuntu,
  Compose rendering with the A9 CPU caps, the GH-283 gate + mutation regression,
  and the site CSS gate on hosted runners. Later head `f737c7b` (action SHA
  pins) still needs one hosted run.

### 2026-09-30 — MS-B decision record proposed (Claude stand-in, delegated)

- `docs/architecture/ms-b-contract-decisions.md`: D1–D7 for #276 with a
  verified pinned-silverc capability baseline (tx.time→CLTV, this.age→CSV,
  input/output amount introspection, checkSig/checkSigFromStack, no runtime
  cross-contract calls). Binding only after Codex architecture review; child
  issues listed for Codex to open; all outcomes ship as one "contract bundle v2".
- Second hosted verification at `40dfd89`: CI `36702356697` + Security
  `36702361053` all green (covers action SHA pins and PRM-12 code changes).

### 2026-09-30 — Contract bundle v2 draft started (Claude stand-in)

- Branch `agent/claude/contract-bundle-v2-draft` (on top of the stand-in
  branch, head `2f132e4`): ValidatorStakingState enforces the 7-day cooldown on
  chain via `this.age` (CSV, semantics verified in pinned rusty-kaspa), opens
  the PRM-13 exit and rejects a zero withdrawal marker; 58 runtime tests pass.
  Local contract CI 16/17: only the H-001 canary-profile step fails because
  the deployer pins the v1 bundle manifest. The profile split (recommendation:
  verify committed H-001 evidence instead of regenerating) is left to Codex.
  Report `.fleet/reports/bundle-v2-draft-validator-staking.md` (on that branch).
- Bundle v2 draft steps 3–4 (`4a13fa3`, `581f6a0`): RuleStorageState and
  CommunityDonationsState use attested submissions/tallies with ≥50 %
  participation, chain-bound times, value-backed donations and exact recipient
  payouts; failed disbursement votes now end REJECTED. 72 runtime tests pass.
  Finding: pinned silverc misaddresses the stack after `byte[](v, 8)` inside a
  hashed concatenation (runtime InvalidPubkey); `byte[8](v)` works.
- Bundle v2 draft steps 5–6 (`4f39515`, `47b712c`): GovernanceAutoTuning
  autoTune bound to tx.time; DevIncentivePool gets a governance key and
  attested grant finalization with REJECTED path. All five state contracts now
  carry their MS-B draft changes; 73 runtime tests pass.

### 2026-09-30 — Codex handback review started

- Codex reviews stand-in security changes and hosted evidence; Kimi owns the
  independent read-only contract-draft review (handback-contract-review).
- Claude remains the preferred implementation worker. The next brief follows
  review findings; historical H-001 evidence remains frozen.
- State: `HANDBACK REVIEW IN PROGRESS / NO MERGE OR DEPLOY YET`.

### 2026-09-30 — Codex accepts stand-in work with bounded follow-ups

- PR #284 merged normally as 3a79bfe. Stand-in changes are replayed on the
  dedicated handback integration branch; source branches remain preserved.
- Codex accepted dependency locking, strict deployer formats, action pins and
  container defaults after focused review; 98 gate tests passed. Hosted runs
  36702356697 and 36702361053 at 40dfd89 independently confirmed via API.
- Claude owns the scoped retired-worker cleanup fix. Kimi review dispatch and
  canonical probe both returned token_limited; Codex reviewed the draft.
- Contract draft remains unaccepted pending targeted authorization, elapsed
  time and terminal-state repairs, followed by H-001/v2 profile integration.
  Claude remains primary development worker; no duplicate implementation.

### 2026-09-30 — handback-sw-scope-fix (Claude)

- Retired worker cleanup scoped to the exact legacy cache `prometheus-v1`;
  unrelated origin caches preserved. Browser regression green, fails on the old
  worker. Report: `.fleet/reports/handback-sw-scope-fix.md`. No merge or deploy.

### 2026-10-04 - landing-status-20261004 delivered (Claude)

- Branch `agent/claude/landing-status-20261004` on main e6d5464: two factual
  roadmap rows on the public landing; waiting on Codex review. Proposal: a
  separate site-wide claim reconciliation after the contract-v2 review.

### 2026-10-04 - landing-status-20261004-correction delivered (Claude)

- Branch `agent/claude/landing-status-20261004-correction`: wording per Codex
  review; screenshot evidence preserved; waiting on Codex UI review. Next for
  Claude: C2 (K1 follow-up), sequenced after this write.

## 2026-10-09 - CODEX - C3 started in isolated documentation branch
- Owner-directed solo execution; Claude remains paused. No worker outage or duplicate delegation inferred.
- C3 branch agent/codex/c3-public-claims-20261009 starts from verified main e6d5464a8535a9a3095507501af7f8706c336258. Accepted landing/README commits were reused as 4df4b11, cb2cd5d and 79b25e7; no v2 product changes imported.
- Scope: architecture node public web/docs -> claim consistency verifier -> public status ledger. October reconciliation preserves the immutable August audit and H-001 evidence; historical engineering estimates will not be re-measured by a documentation edit.
- C2 Security Audit37988101662 SUCCESS on exact 3e94ce0. CI37988100086 still IN_PROGRESS; four new engine regressions remain unverified until the runtime log is checked. No additional dispatch.
- PR287 is closed unmerged; current main already contains most honesty corrections. Only useful missing context is consolidated, without replaying stale wording or unsupported panic claims.
- K2 and contract security/trusted-source/acceptance gates remain open. Codex Security NOT CONNECTED / NOT RUN; no deployment, signing, broadcast, infrastructure change or social publication.

## 2026-10-09 - CODEX - C2 exact-head runtime gate passed
- Exact worker head 3e94ce0fa81591d2a0e23758dfc46a735a8b8a92: Prometheus CI37988100086 SUCCESS (8/8 including Rust Performance); Security Audit37988101662 SUCCESS (3/3). Dispatched exactly once each.
- Codex inspected runtime job114015148385 log: all four new donateRuntime boundary regressions actually ran and passed (multiplication, addition, cumulative-total rejection; large in-range donation acceptance). Runtime109 passed, zero failed/ignored. Keyless operator library66, calculation CLI2 and collision6 tests passed; bundle separation/early-gate and complete v1 operator steps passed.
- C2 bounded documentation/runtime follow-up is accepted for integration. Worker branch is not merged; no compiled identity/pin change or full contract/security/deployment acceptance follows. K1 covered original61549b1 only.
- Decisions unchanged: no new donation cap, unused constants remain until a separate source/manifest revision, constructor/cumulative-counter bounds remain a deployment-review gate.
- C3 public-claims consolidation continues independently from main, without v2 code. K2/trusted-source/client allowlist/D1-D7 and rollout gates remain open. Claude paused, Codex Security NOT RUN; no worker dispatch, deployment, chain or infrastructure action.


## 2026-10-09 - CODEX - C3 reconciliation implemented, publishing gate pending
- Reused accepted bc37515 work without importing v2 product changes. Updated README, WHITEPAPER, FAQ/roadmap Markdown and HTML, landing, economics page, llms.txt, sitemap, Memory status and public JSON ledger; added the seventeen-row docs/claim-reconciliation-2026-10-09.md and C2/C3 reports.
- Added exact October evidence/closed-gate drift checks and eleven-surface checkpoint regressions. Immutable August audit, H-001 records, September event dates and historical engineering estimates preserved; no product module, workflow, dependency, contract, pin or tokenomics delta.
- Local public consistency (13 surfaces), hygiene, pin policy, Ruff, verifier mypy and diff checks PASS. Test-module mypy retains five pre-existing findings on unchanged lines, not globally clean. Memory replay 5/5 PASS; full script suite is still running. Full Pages replay aggregate output was not retained and is not claimed as a complete pass.
- Browser gate PASS on five pages/four viewports with 28 screenshots inspected; menu states, clipping/overflow, assets and natural visibility checked. Early animation-timing captures were corrected in the test only; no reveal-trigger/CSS product patch. Durable reproduction/assertions/screenshots are owner-local.
- C2 exact 3e94ce0 CI/Security and 109 runtime tests/four new cases are verified; v2 remains unmerged/non-promotable and full acceptance stays open. Claude paused; K2/trusted-source/client allowlist/D1-D7 and production gates remain open. Codex Security NOT CONNECTED/NOT RUN.
- Next: finish script tests, save scoped self-review, normal documentation PR with required checks, then live Pages verification after an authorized normal merge. Status PARTIAL, no deployment/chain/infrastructure/social action.

## 2026-10-09 - CODEX - C3 local verification complete
- Final stable-source script suite: 401 tests in 1039.438 seconds, OK. Earlier blocked/moving-source attempts were not passes; no assertion or gate weakened. Public consistency, hygiene, pin policy, Ruff, verifier mypy, stale-launch scan and diff checks pass; five unchanged test-module mypy findings remain.
- Scope self-review .fleet/reports/c3-public-claims-review-20261009.md accepts the local implementation only. Twenty responsive page states and 28 screenshots inspected; no UI production-trigger/CSS change. Replay aggregate loss remains explicitly documented, not an invented full replay pass.
- C3 remains PARTIAL for publishing: save exact scoped commit, push task branch, normal PR/required checks, then live Pages verification. C2 candidate remains unmerged and full v2/security/rollout gates remain open; Claude paused, K2 queued, Codex Security NOT RUN.

## 2026-10-09 - CODEX - C3 bounded PR-review correction
- PR288 automated comments independently checked: new llms evidence URLs needed the project prefix; retained negative checkpoints did not themselves reject a conflicting v2 deployment statement. Both fixed within documentation-gate scope.
- Added prohibited positive v2/D5/Rust-v2/Codex-Security claims plus negative-language and intact-checkpoint regressions. Two new tests PASS (28.132s); consistency13, hygiene, Ruff, verifier mypy and diff PASS. Full changed-module suite running; final-head CI required. Prior401 full-script pass belongs to e9316a8, not relabeled as a new-head run.
- No rendered HTML/CSS/JS delta or contract/authority change. Existing responsive evidence remains applicable. New commit/push follows; no duplicate dispatch, admin bypass or release claim.

## 2026-10-10 - CODEX - K2 trust specification prepared
- C3 normal PR288/289 publication is complete at main251307a; CI37997143555 SUCCESS8/8, Security37997143573 SUCCESS3/3 and Pages37997143075 SUCCESS. This task builds from that documentation-only public baseline.
- Owner-directed Codex execution, Claude paused; no worker outage, duplicate assignment or new external code payload inferred. K2 variants supplied locally, not by Kimi; K1 source scope remains61549b1.
- Existing MAP M1/MS-B node: reviewed plan -> genesis identity -> observed candidate -> closed acceptance. Four proposed variants, source/network/reorg/provenance/expiry criteria, 26 adverse cases and six dependent follow-up tickets documented.
- Current v2 implementation is referenced at unmerged C2 head3e94ce0, not imported. Source, contracts, pins, immutable evidence, policy, runtime, client and tokenomics unchanged. No source capture, deployment, signing or chain/network mutation.
- Static diff/matrix/source checks pass; local target tests NOT RUN because macOS rejects requested memory bound before test launch; PlantUML not installed, source only. Hosted required checks/publication pending; no manual dispatch.
- Model selection, source approval, policy thresholds, constructor/D1-D7/full v2/D5 acceptance, later independent review and rollout remain open. Codex Security NOT CONNECTED/NOT RUN; specification is not a gate exemption or activation.
- Report .fleet/reports/k2-d5-trust-spec-20261010.md; scoped self-review recorded separately. Documentation task PARTIAL until normal PR verification; full project NOT_COMPLETE.
