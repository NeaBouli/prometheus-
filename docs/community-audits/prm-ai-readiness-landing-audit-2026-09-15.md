# Prometheus — AI-Readiness & Landing Quality Audit

- **Series:** Collateral Web3 Open Audits
- **Date:** 2026-09-15
- **Target:** live `neabouli.github.io/prometheus-/` + website source @ `8b5da58a34172062cf644db52ba459385d151562`
- **Scope:** llms.txt, robots.txt, sitemap.xml, JSON-LD, meta/OG, service worker SEO impact, landing HTML/CSS build quality (user-reported "uncoordinated/unattractive layout" — documented objectively), accessibility
- **Method:** deep-recon agent + lead verification (live screenshot analysis, CSS rule tracing, contrast computation, live probes)
- **Register:** PRM-43 … PRM-48 (this report) — **0 Critical / 0 High / 2 Medium / 3 Low / 1 Info**

---

## Executive summary

The AI-facing anchors are strong where the project's own pipeline maintains them: llms.txt (v1.2, 97 lines) fact-checks clean against README, all five JSON-LD blocks validate, the sitemap is complete with accurate lastmods, and robots.txt explicitly allows AI crawlers. The user-reported layout problem has an objective root cause, and it is not taste: **duplicated CSS rule blocks pasted into the same `<style>` sections override text colors to `#333333` on a `#050505` background — 1.61:1 contrast, effectively invisible** — on top of five divergent per-page stylesheets with no shared design system. The fabricated dashboard (PRM-28) also leaks into this layer: llms.txt steers AI crawlers to it.

## Severity table

| ID | Severity | Title |
|----|----------|-------|
| PRM-43 | Medium | Duplicated CSS rule blocks override text to 1.61:1 contrast (near-invisible) — the objective cause of the "uncoordinated/unattractive" complaint |
| PRM-44 | Medium | No design system: five divergent per-page `<style>` blocks (9–18 KB each, ~25–55% pairwise overlap) + ad-hoc dashboard CSS |
| PRM-45 | Low | llms.txt pages section omits guardian-economics.html and includes the fabricated Audit Dashboard (steers AI to fake stats) |
| PRM-46 | Low | robots.txt uses retired `Claude-Web` token; missing modern AI crawler tokens; no ai.txt / security.txt |
| PRM-47 | Low | HTML validity/accessibility: duplicate `id="hybrid-routing"`, missing id on card 5, 17 `target="_blank"` without `rel="noopener"`, no skip-link, 1.4–1.6 MB hero images |
| PRM-48 | Info | Hero design note (100vh grid-rows, animation-gated content); JSON-LD all valid; sitemap accurate; deep-link anchors mostly complete |

---

## PRM-43 — Medium — Duplicated CSS rules render text near-invisible (the layout complaint's root cause)

**Evidence (lead-verified):** `index.html:130` declares `.f-links a{…color:#4A5040…}` and `:203` re-declares `.f-links a{…color:var(--dim)…}` — the later copy wins; `--dim: #333333` (`:55`) on `--void: #050505` (`:40`) computes to **1.61:1 contrast** (WCAG AA requires 4.5:1). The agent machine-counted **32 duplicated selectors** in `index.html:112-134` (`.b-plan`, `.f-left`, `.cta-meta`, `.tok-k`, `.metric-k`, `.rm-date`, `.rm-desc`, `.hero-stat-key`, `nav`, `.layer-idx`, …) resolving footer text/links, "Planned" badges, token-row keys and CTA meta to the same near-invisible value; `--muted: #666666` reaches only 3.55:1 — also below AA. Git history shows the mechanism: commits `a431604` and `76f4c7d` pasted additional rule blocks instead of editing originals. Same disease on the other pages: roadmap 9 duplicates, guardian-economics 6, faq 3, whitepaper 2.

**Impact:** real content (footer links, plan badges, token explanations, roadmap dates) is effectively unreadable on the live site — this, not the (deliberate) dark avant-garde hero, is what reads as "uncoordinated and unattractive".

**Recommendation:** delete the duplicate blocks (keep the first declarations), extract one shared stylesheet, add a contrast lint (e.g. stylelint a11y plugin) to CI — the project already has the discipline to gate this; it just gates docs, not CSS.

## PRM-44 — Medium — No design system: five divergent per-page `<style>` blocks

**Evidence:** each of the five main pages embeds its own 9–18 KB `<style>` block with only ~25–55% pairwise line overlap (agent-measured); no shared CSS file exists (`ls *.css css/ assets/` → none). Inline `style=` attributes are rare (index 2, roadmap 6, whitepaper 2 — mostly `onerror` image fallbacks), so the problem is **copy-divergence of five embedded stylesheets**, not inline styling. The audit dashboard adds a sixth ad-hoc CSS with no meta/OG/canonical/JSON-LD at all (PRM-28 covers its content). Every token change (color, spacing, nav) must be edited in five+six places — the duplication in PRM-43 is the predictable outcome.

**Recommendation:** one `site.css` (design tokens + shared components) + per-page small overrides; Pages-served, fingerprinted.

## PRM-45 — Low — llms.txt pages section steers AI to the fabricated dashboard, omits a page

**Evidence (lead-verified):** `llms.txt:67-73` lists Homepage, Whitepaper, FAQ, Roadmap, **Audit Dashboard** (`:72`, the fabricated page — PRM-28) and GitHub, but **omits `guardian-economics.html`** (a main nav page with valid TechArticle JSON-LD). The rest of llms.txt fact-checks clean (GH run IDs, tokenomics, hardware, 60s-target framing, do-not-cite list). Fix the underlying page (PRM-28) and this reference together.

## PRM-46 — Low — robots.txt / ai.txt / security.txt

**Evidence:** `robots.txt` allows GPTBot, PerplexityBot, Googlebot and "**Claude-Web**" — the retired crawler token (current: `ClaudeBot`); missing common explicit allows (`OAI-SearchBot`, `ChatGPT-User`, `Google-Extended`, `CCBot`); no `ai.txt` exists (live 404 — optional); no `.well-known/security.txt` (would complement the otherwise well-wired SECURITY.md).

## PRM-47 — Low — HTML validity & accessibility cluster

**Evidence (agent-swept, lead spot-checked):** `guardian-economics.html:412` and `:419` duplicate `id="hybrid-routing"` (invalid; sidebar resolves to the first); solution card #5 (`:447`, "Incentivized Cloud Pooling") has no id → cannot be deep-linked, missing from sidebar nav; 17 `target="_blank"` links without `rel="noopener"` across pages; `index.html:258` logo `href="#"`; no skip-to-content link. Positives verified: `lang="en"` everywhere, viewport, exactly one h1 per page, no heading-level skips, all images have `alt`, burger button has `aria-label`, parser found no unclosed/stray tags and no dead in-page or cross-page anchors. Performance-adjacent: `Prometheus.png` (1.4 MB), `prom_coin.png` (1.6 MB), `kas_coin.png` (2000×2000) are heavy for hero/OG/icon use.

## PRM-48 — Info — Hero design note; verified anchor strengths

The 100vh hero with `grid-template-rows:1fr auto` + radial-mask grid + 14%-opacity ambient logo is a deliberate design (verified in CSS, `index.html:73-96`), with headline/subline/actions gated behind staggered `opacity:0 → rise` animations — in no-JS/print/reduced-motion contexts the initial state can read as an empty black page (the first screenshot of this audit looked broken until animations ran). Design choice, not a defect; a `@media (prefers-reduced-motion)` fallback would make it robust. Verified strengths: all 5 JSON-LD blocks parse (SoftwareApplication `version: "4.0"` matches whitepaper v4.0; dateModified 2026-09-13 consistent); sitemap complete for all 6 public HTML pages with accurate lastmods; FAQ/economics deep-link anchors present (except PRM-47); GSC file verification works (PRM-32 covers the dead meta tag).

---

## Verified strengths

- llms.txt v1.2 is factually accurate against README (independently spot-checked) and explicitly instructs AI assistants on claim discipline ("do-not-cite" list) — a best-practice pattern this series recommends other projects adopt.
- JSON-LD coverage and validity on all five main pages; canonical/OG/twitter cards complete.
- Sitemap↔page set coherent; lastmods honest (dashboard correctly shows 2026-03-22).
- Accessibility fundamentals (lang, h1 structure, alt texts, aria on the burger) are in place — the failures are contrast (PRM-43) and a few validity nits (PRM-47), not structural neglect.
