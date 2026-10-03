id: landing-status-20261004 (self-proposed under Gio's rule "Landing aktuell halten", 2026-10-04)
status: ok (pending Codex review; no hosted dispatch until Codex coordinates)
worker: claude
branch: agent/claude/landing-status-20261004 (base origin/main e6d5464)
architecture_node: public site -> index.html roadmap (06 / Roadmap)
change: two roadmap rows in index.html, nothing else:
  - "Community audit remediation (PRM-01…PRM-48)", Sep 2026, badge Merged: #270 register; PR #284 exact main 3a79bfe (CI 36766270695, Security 36766270804, Pages 36766269974); PR #285 exact main e6d5464 (CI 36769372160, Security 36769372493, Pages 36769371268); contracts/H-001 evidence/tokenomics/production unchanged; no deployment or production claim. Facts from `gh pr view` and `gh run list --branch main`.
  - "Contract bundle v2 decisions (MS-B, #276)", Oct 2026, badge In progress: proposed draft on reviewed worker branches, not merged; v2 non-promotable, Rust deployer pins only the H-001 v1 manifest; D5 offline covenant-id calculation and observed-only evidence candidates, acceptance gate closed; independent security review in progress; no deployment/chain/production claim.
not changed (deliberately): footer "Project status reviewed 2026-09-13 · base 5cd13bf" and JSON-LD dateModified. scripts/verify_public_claim_consistency.py pins LATEST_PROJECT_UPDATE and the 5cd13bf reconciliation baseline across all HTML pages; bumping them implies a full site-wide claim reconciliation, which is a separate decision (proposal for Codex below).
visual release gate (frontend-visual-release-gate): Playwright/Chromium 1243, local static server, viewports 1440x1000, 1180x820, 820x1180, 390x844; assertions per viewport: document horizontal overflow 0, rm-desc scrollWidth == clientWidth (no clipping), badges visible within viewport, no page errors -> all pass. Screenshots inspected (roadmap section incl. neighbours GH-253 and readiness row): typography, spacing, borders, badge treatment and wrapping match existing rows; mobile capture shows the pre-existing fixed nav over an older row (capture artefact, not a layout change).
tests:
  public gates: documentation hygiene, public-claim consistency, project-status consistency, memory integrity, verify_site_css -> PASS
  local CI replay pages-check + memory-check -> pages-check 7/7 PASS, memory-check 5/5 PASS
proposal_for_codex: if wanted, a separate block "site-wide claim reconciliation 2026-10" to bump the review date/baseline on all pages and the gate constants together, after the contract-v2 review.
not changed: other pages, contracts, pins, evidence; no deployment.
