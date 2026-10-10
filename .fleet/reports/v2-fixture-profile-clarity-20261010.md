# M2-DOC-V1-V2-COOLDOWN

status: partial
owner: Codex (sole implementation owner; no nested agents)
base: 649e4959586dd72b81a539df620802cecae9bfe3 (held Docs296)
branch: agent/codex/v2-fixture-profile-clarity-20261010
security: none (documentation only; no new security review claim)

## Summary And Scope

Existing architecture-map node: contract-fixture documentation -> modules/web
public-web render hop. Skills read: fleet-developer, architecture-map,
frontend-visual-release-gate; applicable public AGENTS.md/CLAUDE.md and bridge
guidance read in the dedicated worktree. No architecture or source node changed.

Modified public surfaces: WHITEPAPER.md, docs/validator-guide.md, index.html,
whitepaper.html. Appended records: memory/AUDIT.md, memory/STATUS.md,
.fleet/PLAN.md, docs/agent-bridge/ACTION_LOG.md. Added this report only; supplied
task file preserved. Canonical checkout untouched; no commits or remote writes.

All four surfaces distinguish frozen historical h001-v1 (100,800) from
unaccepted, non-promotable v2-draft (6,048,000). Approximate 2.8 hours and 7 days
explicitly assume 10 consensus-score units/s, not guaranteed wall-clock time.
No fully deployed historical protocol, production readiness, new accepted
duration, v1 release-pin replacement, D1-D7 adoption or activation is claimed.
The validator-guide withdrawal sequence is labeled fixture-only, not live
network operation. No links into an unmerged historical bundle were introduced.

Source constants inspected read-only: historical
modules/contracts/silverc/bundles/h001-v1/sources/ValidatorStakingState.sil:18
retains 100800; draft modules/contracts/silverc/ValidatorStakingState.sil:18
uses 6048000. No source, config, fixture, contract, workflow, policy, pin, CSS,
JS or date-baseline edit. No private managed scan/operator data read or exposed.

## Actual Checks

- `git rev-parse HEAD`: exact requested base; branch unchanged.
- `git diff --check`: PASS before records and at final handoff.
- External trusted Node harness `validate.cjs`: all four surfaces contain the
  required literal claims; arithmetic is 2.8h and 7d at the explicit assumption.
  Inline script/style blocks are byte-identical to base; entire tracked assets
  tree byte-identical. Scope/append-only/static final checks in scope-check.json.
- Installed Playwright with installed Chromium1243, sandbox enabled, fresh
  ephemeral profile and sterile process environment. No installation, repo
  module import or repository-controlled test/build execution. Loopback server
  allowlist: two pages and their existing local CSS/logo assets; no other routes.
  External requests intercepted; dead loopback proxy/DNS block also configured.
- Eight cases: both pages at1440x1000,1180x820,820x1180,390x844. HTTP200,
  zero page/console errors, page scrollWidth <= viewport, changed text visibility,
  Range geometry/ancestor clipping, hit-test obstruction and contrast measured.
  Focus outline plus keyboard Enter navigation tested: desktop Whitepaper
  validator anchor; tablet/mobile visible breadcrumb; Index Whitepaper link
  through mobile menu where appropriate. All navigation/focus checks PASS.
- Index four cases PASS; minimum contrast5.9038:1. Whitepaper desktop/tablet
  three cases PASS; minimum contrast8.3982:1. Whitepaper390x844 FAILS changed
  text clipping: row x24,width384.40625,right408.40625 against viewport390;
  ancestor clipping detected despite document scrollWidth390. Existing mobile
  table uses overflow-x:auto; no overflow hidden or assertions weakened.
- Harness final exit2 correctly reports the failed visual assertion. Initial
  harness chose the hidden desktop Index link at820px and timed out; first-run
  results retained, handles closed. Harness corrected to exercise the actual
  mobile menu, with explicit timeouts. No product workaround or unsafe retry.
- All eight final screenshots opened and visually inspected individually.
  Index mobile is dense but complete; Whitepaper mobile visibly truncates
  the right side of the changed paragraph. No green release assertion.
- No local Rust/Python suites, arbitrary repository tests or builds run.
  Hosted exact-head tests/publication are Core-owned and NOT RUN here.

## Evidence And Risks

Permanent evidence directory (mode700):
/Users/gio/agent-fleet/evidence/prometheus/v2-fixture-profile-clarity-20261010

Artifacts (mode600): validate.cjs, check-scope.cjs, results.json, first-run-results.json,
scope-check.json, and the eight PNGs:
index-{1440x1000,1180x820,820x1180,390x844}.png;
whitepaper-{1440x1000,1180x820,820x1180,390x844}.png.
The supplied task file was not modified. Browser/server sessions completed;
fresh temporary profile/home/cache output removed, permanent evidence retained.

risks: Whitepaper390x844 existing table clips changed text; CSS repair is outside
the permitted patch, so the visual release gate remains blocked. Google Fonts
stylesheet was substituted with empty CSS to avoid external network; fallback
font results do not establish hosted-font layout parity. Independent semantics,
exact-head hosted CI/Security, publication and post-deploy checks remain pending.

next: Core decides the separately authorized mobile layout correction, performs
narrow semantic/evidence review, owns any independent exact backport, final
commit/push and fresh hosted CI/Security/Pages gates. Parent-reported parity
between base649e495 and main752f58b is integration context, not a worker claim
of main adoption or public deployment. All acceptance/activation/product limits
remain unchanged; no full rollout readiness follows from this text patch.

## Core-Amended Final Checkpoint (Same Task, 2026-10-10)

status: ok (worker-owned amended scope only; supersedes partial blocker above)
security: none (semantic documentation verification, not a vulnerability review)

The original partial report and all original evidence remain intact. Core's
appended task amendment authorizes the smallest Whitepaper-local table fix and
historical time-input clarification; same owner, branch and immutable base.
No rebuild/restart, new task, additional agent, commit/push or publication.

### Semantic Correction

The earlier "These are consensus-score values" claim is superseded, not an
assertion about frozen v1 consensus enforcement. Direct read-only source:
historical ValidatorStakingState.sil requestWithdraw:139-158 stores the supplied
block_height; completeWithdraw:163-169 accepts block_height as an argument and
checks it against stored withdraw_request_block +100800. The parameter in this
actual frozen source is named block_height, not current_block; its caller-supplied
count is not a consensus-enforced DAA input. Draft completeWithdraw:181-190
instead requires this.age >=6048000 on the withdrawal UTXO; the relevant public
contract README:67-69 identifies the OP_CHECKSEQUENCEVERIFY path.

All four public surfaces now carry the same complete claim: frozen historical
h001-v1 uses the100,800 caller-provided count; unaccepted, non-promotable
v2-draft uses6,048,000 consensus DAA-score age units. Nominal approximately
2.8 hours/7 days assumes10 count units/s for v1 and10 DAA-score units/s for v2,
never guaranteed wall time. No historical full deployment/production readiness,
new accepted duration, release-pin replacement, D1-D7 adoption or activation.
Validator-guide sequence is fixture-specific request/completion, not a live
instruction or a claim that frozen current-silverc methods are named withdraw().

### Local Layout Delta And Final Verification

Only three new inline CSS lines, inside whitepaper.html's existing <=900px
media block, scope to #validators .wp-table: display:table/table-layout:fixed,
normal whitespace/overflow-wrap:anywhere for cells, first-column width34%.
No content/columns removed, overflow hidden, shared CSS/JS/asset change or
unrelated UI repair. Original inline CSS outside these exact lines is byte-identical;
all inline JS, HTML event/style/link attributes and tracked assets remain exact.

Corrected validate.cjs uses the same trusted installed sandboxed browser,
sterile environment, fresh profile, allowlisted localhost serving and blocked
external network. Previous focus/clipping/contrast assertions retained, plus
stronger all-table-cell text geometry, two-column and zero horizontal-scroll
regressions. Read-only frozen/draft source literal assertions PASS; all four
normalized claims agree exactly, numeric arithmetic unchanged.

Actual rerun exit0: eight cases PASS, both pages at1440x1000,1180x820,820x1180,
390x844. HTTP200, zero page/console errors, no page overflow, clipping or
obscured changed text; focus outline and keyboard/mobile-menu navigation PASS.
Whitepaper all-table-cell horizontal fit/zero-scroll assertions PASS at all
four sizes. Exact mobile regression: row x24,width342,right366, viewport390;
table scrollWidth/clientWidth342, two columns. Minimum contrast unchanged:
Index5.9038:1, Whitepaper8.3982:1. All eight corrected images opened individually;
the full changed text is visible, including the final rollout limitation.

Final static scope/append-only checks PASS, including preservation of earlier
report/record byte prefixes, amended supplied task and every original partial
evidence artifact. No arbitrary repository suite/build or target-code execution.
Worker browser/server sessions exited, temporary sterile home/profile/cache
output removed. No source/config/fixture/contract/pin/workflow/dateBaseline change.

### Corrected Evidence And Remaining Limits

New permanent private700 directory:
/Users/gio/agent-fleet/evidence/prometheus/v2-fixture-profile-clarity-20261010/corrected
Private600 artifacts: validate.cjs, check-scope.cjs, snapshot.cjs,
previous-checkpoint.json, results.json, scope-check.json and eight fresh PNGs:
index-{1440x1000,1180x820,820x1180,390x844}.png;
whitepaper-{1440x1000,1180x820,820x1180,390x844}.png.
Original evidence remains in the parent directory under original names.
Exact modified source paths remain the four public surfaces and four bounded
append-only records listed above, plus this append-only report; no task edits.

risks: No remaining observed local clipping blocker. External Google Fonts
were not fetched (fallback-font-only evidence); hosted-font/layout parity,
independent semantic review, exact main-based transplant, hosted CI/Security,
Pages publication and post-deploy checks remain Core-owned and not run here.
No public deployment, main adoption or broader acceptance is claimed.

next: Core reviews the exact finished delta and independently transplants it
onto its main-based branch, then owns final commit/push and fresh exact-head
hosted gates/publication. Existing source/D1-D7/activation/product limits remain.
