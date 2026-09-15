# Prometheus — Integration & Surfaces Audit

- **Series:** Collateral Web3 Open Audits
- **Date:** 2026-09-15
- **Target:** NeaBouli/prometheus- @ `8b5da58a34172062cf644db52ba459385d151562` + live `neabouli.github.io/prometheus-/`
- **Scope:** public Pages site incl. audit dashboard, service worker, PWA manifest, evidence anchors (Testnet-10 explorer), third-party integrations
- **Method:** deep-recon agent + lead verification incl. live probes (anonymous GET/HEAD only); 10/10 site files byte-verified identical between live and baseline
- **Register:** PRM-28 … PRM-33 (this report) — **0 Critical / 1 High / 2 Medium / 2 Low / 1 Info**

---

## Executive summary

The project's public surface is privacy-clean (zero third-party scripts on any page; only Google Fonts stylesheets) and byte-fresh (every live file identical to baseline). One surface breaks the project's own discipline spectacularly: the **"Open Audit Dashboard"** — site-wide linked from every footer, README, llms.txt and the sitemap — displays fabricated validators, fabricated kaspa addresses, fabricated PROM grants and the claim "All data verifiable on-chain" while containing **zero JavaScript**. It survived because it is excluded from all 13 surfaces of the project's own claim-consistency checker. Separately, the service worker is wired to the wrong paths and has never been able to install, and the Testnet-10 explorer anchoring the H-001 evidence is currently down.

## Severity table

| ID | Severity | Title |
|----|----------|-------|
| PRM-28 | High | Public "Open Audit Dashboard" is fabricated — fake validators/rules/PROM grants, "verifiable on-chain" with zero JS, site-wide linked, excluded from all consistency gates |
| PRM-29 | Medium | Service worker precache uses root-absolute paths (never installs); cache-first + unbounded cross-origin runtime caching by design |
| PRM-30 | Medium | Testnet-10 explorer (public evidence anchor for H-001 canary) currently down (402 DEPLOYMENT_DISABLED) |
| PRM-31 | Low | Dashboard broken logo image (404 via `../../../`); guardian-economics.html missing SW registration + `ai-status` meta; manifest icon sizes wrong |
| PRM-32 | Low | Google Search Console meta-tag token non-functional (filename used as token; file method works) |
| PRM-33 | Info | Positive: zero third-party scripts anywhere; only Google Fonts stylesheets; all in-repo images exist |

---

## PRM-28 — High — Public "Open Audit Dashboard" is fabricated

**Evidence (lead-verified):** `modules/web/audit/index.html` (live, byte-identical to baseline):
- Stats grid (`:121-140`): "**12** Active Validators · **8** Active Guardians · **3** Rules On-Chain · **0.12%** False Positive Rate · **4.2s** Avg Response Time" — none of these systems exist per `README.md:15` ("no production Prometheus network is operating") and `README.md:123` ("no operated validator network").
- Rules table (`:156-180`): three fabricated rules with fabricated `kaspa:qz8f…3a2c` / `kaspa:qr4d…7b1e` addresses, consensus percentages and 2026-03-21/22 timestamps.
- Grants (`:185-196`): "Grant #1 … **1,500 PROM** … APPROVED", "Grant #2 … **3,200 PROM** … VOTING" — while PROM minting is documented everywhere as **not implemented**.
- `:200`: "**Updates every 30s from Kaspa L1 | All data verifiable on-chain**" — the page contains **zero `<script>` tags** (grep-verified: fully static).
- `:204` footer: "Open Source | Decentralized | **Incorruptible**" — precisely the absolutes the project's own 2026-08-14 claim audit banned.
- **Why it survived:** the page is absent from all 13 surfaces in `scripts/verify_public_claim_consistency.py:24-38`, from the documentation-hygiene checker, and from the sitemap freshness gate — the claim audit verified only "five public HTML pages". Yet it is linked from **every page footer** ("Audit"), `README.md:351`, `llms.txt:72` and `sitemap.xml:29`. Untouched since 2026-03-22 (pre-dates the claim audit by ~5 months).

**Impact:** the single most visible "proof" surface of a project whose entire credibility model is claim discipline shows fabricated network state to every visitor and AI crawler (llms.txt steers to it, see PRM-45). For a threat-intelligence protocol this is worse than a missing dashboard — it demonstrates exactly the kind of unverifiable claim the project promises never to make.

**Recommendation:** take the page offline or replace it with the real, labeled evidence data (the project has genuine, well-structured evidence JSONs under `docs/evidence/`); add the page to the consistency-script surface list and the hygiene gate so it cannot drift again.

## PRM-29 — Medium — Service worker broken precache + staleness-prone design

**Evidence (lead-verified):** `sw.js:2-11` — precache asset list uses **root-absolute** paths (`/`, `/index.html`, `/faq.html`, `/roadmap.html`, `/whitepaper.html`, `/logo/Prometheus.png`, …) while the site lives under `/prometheus-/`. Live probe: `https://neabouli.github.io/index.html` → **404**, so `cache.addAll` rejects and **the SW never installs** (single-commit history, `20e8531` — paths were never correct, so no client has ever activated it). Design issues that matter once paths are fixed: cache-first for **all** requests (`:19-30`) with `CACHE='prometheus-v1'` never bumped since 2026-03-22 while all five pages changed repeatedly (incl. the entire claim-audit correction) → any installed client could be pinned to pre-audit pages indefinitely; runtime caching stores every response incl. cross-origin (Google Fonts) with no cap/expiration; no `skipWaiting`/`clients.claim`. Registration is also inconsistent: `guardian-economics.html` never registers the SW (grep: 0 vs 2 on the other pages).

**Recommendation:** fix scope-relative asset paths and bump the cache name per deploy — or drop the SW entirely (the content is static and freshness-sensitive); if kept, gate runtime caching to same-origin GETs with a cap.

## PRM-30 — Medium — Testnet-10 explorer (public evidence anchor) currently down

**Evidence (lead live-probe 2026-09-15):** `https://explorer-tn10.kaspa.org/api/transactions/c85fd1e7…c22f` → **402 "Payment required / DEPLOYMENT_DISABLED"**; the human URL in the evidence JSON (`docs/evidence/gh-9-h001-canary-confirmed-2026-08-12.json`) returns the same. The H-001 canary evidence is internally consistent and well-structured (schema, request/artifact/script SHA-256 set, tx id, block hash, DAA score), but its **public independent re-verification path is currently unavailable** — a third-party infrastructure outage (kaspa.org), not a project defect. Worth recording because the README's "independently observed" wording depends on it.

**Recommendation:** record the explorer-outage contingency in the evidence README (secondary API mirror or signed operator attestation); re-verify the tx when the explorer returns.

## PRM-31 — Low — Dashboard/logo, SW-registration and manifest hygiene

- `modules/web/audit/index.html:112` references `../../../logo/Prometheus.png` → resolves to `neabouli.github.io/logo/Prometheus.png` → **live-verified 404** (masked by `onerror`).
- `guardian-economics.html` is the only main page without SW registration and without the `ai-status` meta the others carry.
- `manifest.json` declares icons `512x512`; the actual files are **1024×1024** (and 1.4 MB — heavy for a maskable icon); no explicit `scope` (defaults happen to be correct).

## PRM-32 — Low — Google Search Console meta-tag token non-functional

All pages carry `<meta name="google-site-verification" content="googleaa2902079481c7a8">` — the **filename** of the verification file (`googleaa2902079481c7a8.html`), not a real GSC meta token. The file method itself is valid and works; the meta tag is dead weight (harmless).

## PRM-33 — Info — Positive integration posture

Zero third-party **scripts** on any page (agent swept all six pages); only Google Fonts stylesheets on the five main pages — an unusually clean third-party posture for a crypto project site (compare STX-29 in the Stealth audit). All in-repo images referenced by the main pages exist. Canonical/OG/twitter meta complete on the five main pages.

---

## Verified strengths

- Site↔repo byte-freshness: 10/10 probed files identical live vs baseline (index, faq, roadmap, whitepaper, guardian-economics, llms.txt, sitemap.xml, sw.js, manifest.json, audit dashboard).
- HSTS served on the github.io origin; real 404s return 404.
- Evidence discipline: `docs/evidence/*.json` files are schema-versioned, hash-anchored, and honestly scoped ("does not independently prove host separation…"); sample files (`deploy-receipts.sample.json`, `metrics-oracle-report.sample.json`) are fully synthetic (`ci_fixture`, sandbox network, patterned txids) — **no leaked data anywhere**.
- The IP-address inventory is clean: only RFC-5737 documentation ranges and loopback/wildcard examples repo-wide; no internal hosts, tokens, or operator secrets found.
