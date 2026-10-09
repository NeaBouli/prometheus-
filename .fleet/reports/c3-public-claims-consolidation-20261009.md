# C3 Public Claims Consolidation

status: partial (implementation verified; publishing checks still pending)
owner: Codex, direct owner assignment; Claude remains paused
branch: agent/codex/c3-public-claims-20261009
baseline: e6d5464a8535a9a3095507501af7f8706c336258
architecture: public web/docs -> public-claim verifier -> post-audit ledger
security: no contract/crypto/authorization/runtime policy change

## Delivered

Reused accepted landing/README work from bc37515, retaining exact merged A1-A8
evidence and open register #270. Added a seventeen-row claim reconciliation,
real development capabilities, explicit historical percentages, synchronized
October metadata and a pinned machine ledger. Historical audit and H-001
records remain unchanged. The new gate rejects evidence/authority drift,
including boolean/integer substitutions and a missing checkpoint on any of
the eleven dated surfaces. The two module READMEs retain their existing
evidence boundaries; the full verifier covers thirteen surfaces.

C2 actual hosted execution is recorded separately. Its verified branch remains
unmerged/non-promotable; no deployment or full contract acceptance is inferred.
No unsupported panic count/distribution from the closed PR287 is included.

## Actual Verification

| Command | Actual result |
| --- | --- |
| python3 scripts/verify_public_claim_consistency.py | PASS, 13 synchronized surfaces |
| python3 -m unittest discover -s scripts -p 'test_*.py' | PASS on e9316a8 before the bounded PR-review delta, 401 tests in 1039.438 seconds, zero failures |
| Existing ci.yml memory-check/pages-check run-step replay | Memory 5/5 PASS; first five Pages steps PASS; final aggregate output not retained. The full script suite separately passes the synchronized-claims unit tests; the stale-launch check separately passes. Not claimed as one complete replay |
| ruff check scripts/verify_public_claim_consistency.py scripts/test_public_claim_consistency.py | PASS |
| mypy scripts/verify_public_claim_consistency.py | PASS, no issues |
| mypy scripts/test_public_claim_consistency.py | Five pre-existing findings on unchanged test lines; no new finding or suppression |
| python3 scripts/check_public_documentation_hygiene.py | PASS |
| python3 scripts/verify_toolchain_pins.py | PASS; pins unchanged |
| rg -n stale-launch patterns across the nine ci.yml public-launch surfaces | PASS, no stale launch/testnet wording |
| git diff --check | PASS |
| git diff --numstat e6d5464 -- modules .github Cargo.toml Cargo.lock | Empty; no product module, workflow or dependency changes |
| Local Playwright visual gate, five pages/four viewports | PASS, 20 states; no errors, local asset failures, overflow or text clipping; menu open/close passed where displayed |

Local Python is 3.14; hosted workflows use their pinned setup. Full Rust/build
validation of C2 is hosted evidence, not a new local Rust build for this docs
patch. Relevant C3 hosted checks must pass on its own final PR candidate.

## Visual Evidence

Durable owner-local C3 evidence contains the reproduction script,
assertions.json, SHA256SUMS and 28 inspected screenshots: five pages at
1440x1000, 1180x820, 820x1180, 390x844, plus four v2-roadmap and four footer captures.
Only the changed landing was rechecked after the C2 status/estimate wording;
the other sixteen unchanged page states were retained.

Early captures were taken before natural reveal animations completed. Strong
visibility waits reproduced correct rendering, including the mobile roadmap;
no production reveal trigger or CSS was changed, and no DOM class was forced.
Sandbox-blocked socket attempts were not passes; final local fixtures/browser
ran with bounded test permissions. The available app-browser backend could
not navigate/resize local pages, so existing cached Playwright and isolated
Chrome were used. Browser and local server were closed after every run.

## Gates And Next

- Normal PR/required checks and post-Pages exact-byte/critical-layout check.
- C2 stack integration remains separate; D5 trusted-source/activation,
  client allowlist, D1-D7 and full contract/security/rollout acceptance stay open.
- K2 remains queued, not delegated during the owner-directed solo assignment.
- Codex Security planned/NOT CONNECTED/NOT RUN, not GitHub Security Audit.
  Additional external-scan applicability is limited to the future product
  integration gate; no scan transfer/cost approval is inferred by C3 docs.
- Existing coordination work is preserved; only own files enter the task PR.
  No signing, wallet, broadcast, production/infrastructure or social action.

Do not mark Done before required publishing and live verification gates pass.

## Execution Notes

The final stable-source script suite is the pass reported above. Earlier
sandbox-blocked fixture runs and a run crossing an in-progress ledger edit
were not counted as passing results. No gate was disabled or assertion
weakened. Local replay aggregate output loss is documented rather than
converted into a claimed pass. Hosted C3 checks remain a separate requirement.

## Bounded PR #288 Review Correction

Both automated comments were checked against the candidate, not treated as
instructions. The two new llms.txt evidence URLs now include the public-site
project prefix. The October gate rejects positive v2 deployment/promotion,
D5 confirmation, Rust v2 execution and Codex Security success claims even when
the required negative checkpoint is retained. No architecture or authority
changes. Negative-boundary language remains valid.

- Two new regression methods: PASS in 28.132 seconds, including intact
  Markdown/HTML checkpoints plus a conflicting deployment claim, seven
  prohibited examples and eight valid negative boundaries.
- Current public consistency 13 surfaces, hygiene, Ruff, verifier mypy and
  diff checks: PASS. Full changed-module tests and final-head hosted checks
  remain required; the earlier 401 result is not relabeled as a final-head run.
- No rendered HTML/CSS/JS delta after the inspected screenshots; llms.txt is
  machine-facing text. No extra browser run claimed or needed for this delta.
