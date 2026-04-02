# PROMETHEUS — SESSION CHECKPOINT
# Last updated: 2026-04-02
# Purpose: Full recovery document. If Claude (Architect) or Claude Code
# loses context, read this file first. It contains the complete project state.

---

## IDENTITÄT

| Feld | Wert |
|------|------|
| Projekt | Prometheus — Decentralized AI Threat Intelligence |
| Repo | https://github.com/NeaBouli/prometheus- |
| Branch | main |
| Lokaler Pfad | ~/Desktop/prometheus |
| Letzter Commit | 9a8c344 — chore: commit Cargo.lock, logo variants, gitignore cleanup |
| Whitepaper | WHITEPAPER.md (root) + whitepaper.html (styled) |
| Status | Feature-complete. Warten auf Covenant-Hardfork 5. Mai 2026. |
| GitHub Pages | https://neabouli.github.io/prometheus-/ |
| Google Search Console | Verified: googleaa2902079481c7a8 |

---

## ROLLEN

| Rolle | Wer | Aufgabe |
|-------|-----|---------|
| Core Dev | NeaBouli | Triggert Tasks, entscheidet über Sprints |
| Architect / Auditor | Claude (claude.ai) | Architektur, Audit, Antworten auf QUESTION FOR CLAUDE |
| Implementierung | Claude Code | Schreibt Code, Tests, Commits, Pushes |

---

## WAS WURDE BISHER GEMACHT (Gesamtübersicht)

### Sprint 0-8: Code-Basis (alle ACCEPTED)
| Sprint | Status | Deliverables |
|--------|--------|--------------|
| 0 — Setup | ACCEPTED | kaspad v1.1.0 Testnet-10, Repo-Struktur, CI/CD |
| 1 — Contracts | ACCEPTED | 6 Silverscript Contracts (54 Tests), 5 Audit-Fixes |
| 2 — Client | ACCEPTED | Rust: KaspaConnection, KRC-20 Reader, YARA Scanner, ZK-Stub |
| 3 — AI | ACCEPTED | Phi-3 ONNX Wrapper, AnomalyDetector, Fed-DART Client |
| 4 — Guardian | ACCEPTED | Docker vLLM, LLM Server, YARA Generator, Analyzer (Python) |
| 5 — Voting | ACCEPTED | Commit-Reveal, Bond System, SlashingEngine (Rust) |
| 6 — E2E | ACCEPTED | Lifecycle <60s, Sybil 500:1, FP-Flood blocked |
| 7 — Dashboard | ACCEPTED | Audit-Dashboard, README.md, WHITEPAPER.md |
| 8 — Docs | DONE | CONTRIBUTING.md, 5 Wiki-Guides, SECURITY.md |

### Web-Präsenz (alle live auf GitHub Pages)
| Deliverable | Commit | Beschreibung |
|-------------|--------|-------------|
| index.html | aec339d+ | Landing Page — dark theme, mint, ambient logo, KAS+PROM token cards |
| faq.html | af1a06a+ | 19 FAQ-Einträge: Tokenomics, AI Architecture, Security, Participation |
| roadmap.html | af1a06a+ | Phases A-F, Sprints 9-19, Device + Hardware Tables |
| whitepaper.html | 8c950f6 | Full v4 Whitepaper in HTML, 16 Sections |
| guardian-economics.html | 40cde25+ | Hardware-Kosten, Break-Even, 5 Lösungsansätze |
| modules/web/audit/ | dc20deb | Open Audit Dashboard mit Mock-Daten |

### Infrastruktur
| File | Beschreibung |
|------|-------------|
| llms.txt | AI-Crawler Standard (GPTBot, Claude-Web, Perplexity) |
| robots.txt | Alle Bots erlaubt |
| sitemap.xml | 6 URLs mit Priority + Lastmod |
| manifest.json | PWA-Support, 2 Icons (Prometheus + PROM coin) |
| sw.js | Service Worker für Offline-Caching |
| SECURITY.md | Bug Bounty + Disclosure Policy (GitHub only, no email) |
| docs/repository-security.md | Branch Protection Anleitung für Core Dev |
| googleaa2902079481c7a8.html | Google Search Console Verification |

### SEO/GEO auf ALLEN 5 Seiten
- Schema.org JSON-LD (SoftwareApplication, FAQPage, TechArticle, WebPage)
- Open Graph (og:title, og:description, og:image, og:url)
- Twitter Cards (summary_large_image)
- AI-Summary Meta Tags (ai-summary, ai-category, ai-status)
- Canonical URLs, Google Verification, PWA Manifest, Theme-Color

### Mobile Navigation
- Hamburger-Menü auf allen 5 Seiten (CSS + JS)
- Breakpoint 900px, full-screen overlay, auto-close on link click
- 7 Nav-Links + 9 Mobile-Menu-Items (synchronized)

### Logos
| Datei | Verwendung |
|-------|-----------|
| logo/Prometheus.png | Hauptlogo (1.4MB), Nav, Hero, OG-Image (index, roadmap) |
| logo/prom_coin.png | PROM Token (1.6MB), Token-Card, OG-Image (faq, whitepaper, economics) |
| logo/kas_coin.png | KAS Token (84KB), Token-Card |
| logo/promlogo.png | Alternatives Logo |
| logo/promlogo1.png | Alternatives Logo |

**WICHTIG: Dateinamen sind case-sensitive auf GitHub Pages!**
- prom_coin.png (lowercase p) — NICHT PROM_coin.png
- Prometheus.png (uppercase P) — korrekt

---

## OFFENE TODOS (Priorität)

### Für Core Dev (manuell):
- [ ] GitHub Pages aktivieren (Settings → Pages → main / root)
- [ ] Repository public schalten
- [ ] Gitcoin Grants Antrag einreichen (Deadline: April 2026)
- [ ] Discord/Telegram aufbauen
- [ ] Apple Developer Account + Google Play Account (vor Sprint 13)

### Für Claude Code (nächste Session):
- [ ] CI/CD Ergebnis prüfen (https://github.com/NeaBouli/prometheus-/actions)
- [ ] Guardian hybrid routing (8B/70B) — Sprint 10B
- [ ] Ensemble voting protocol (5x 8B majority) — Sprint 10B
- [ ] fp_rate Oracle-Mechanismus entscheiden (Q-003 offen)
- [ ] PATTERN-010 fixen: Arc<Phi3Model> statt Arc<Mutex<Phi3Model>>
- [ ] Sybil resistance final design — Architect decision needed
- [ ] PLONK evaluation for Light Client ZK-proofs

### Wartet auf externe Events:
- [ ] ssc Compiler (Covenant-Hardfork 5. Mai 2026) → Sprint 9
- [ ] Phi-3-mini Modell herunterladen → Sprint 11
- [ ] LLaMA 3 Fine-Tuning → Sprint 12
- [ ] vProgs (DAGKnight) → Sprint 14

---

## KRITISCHE ARCHITEKTURREGELN (nie vergessen)

1. VALIDATORS staken KAS — tx.value = KAS, Konstante = MIN_STAKE_KAS
2. PROM wird VERDIENT (Guardians) — niemals gestaked von Validators
3. Kein Emergency-Stop — by design, kein Killswitch
4. slash() hat ACL: nur GOVERNANCE_CONTRACT oder RULE_STORAGE_CONTRACT
5. float64 → uint64 mit 10000x Skalierung in allen Contracts
6. IPFS CID = bytes(36) binär CIDv1 (nicht bytes(46))
7. Commit-Reveal: sha256(vote_byte || salt_le || block_height_le)
8. cargo fmt + cargo clippy -- -D warnings vor jedem Rust-Commit
9. Testnet = kaspa-testnet-10 (Testnet-12 existiert nicht)
10. ssc Compiler erscheint mit Covenant-Hardfork am 5. Mai 2026
11. Jede neue HTML-Seite: SEO/GEO-Checkliste (Schema.org, OG, ai-summary)
12. Mobile Hamburger-Menü auf jeder Seite
13. GitHub-only Contact (kein Email, kein Discord DM)

---

## ARCHITEKTUR-ENTSCHEIDUNGEN (#1-18)

| # | Entscheidung |
|---|-------------|
| 1 | KAS = Staking-Asset der Validators |
| 2 | PROM = Reputations-/Governance-Token |
| 3 | Kein Emergency-Stop |
| 4 | Keine Foundation, kein Gründer-Pool |
| 5 | Governance: vollautomatisch |
| 6 | Jaeger-KI: LLaMA 3 70B (Pflicht) |
| 7 | Jaeger-KI: LLaMA 3 8B (Fallback) |
| 8 | Waechter-KI: Phi-3-mini 4-bit |
| 9 | Blockchain: Kaspa mit Silverscript |
| 10 | Föderiertes Lernen: Fed-DART |
| 11 | DSGVO: nicht anwendbar |
| 12 | Validator Quorum: 67% (2/3-Mehrheit) |
| 13 | Abstimmung: Commit-Reveal + Salted |
| 14 | Anti-Sybil: Quadratic Voting (Rep^2) |
| 15 | Reporter-Pool: 75% Light / 25% Honeypot |
| 16 | Guardian hybrid routing: 8B default, 70B escalation <0.70 |
| 17 | Ensemble voting: 5+ 8B nodes = alternative zu 1x 70B |
| 18 | Guardian Pooling: on-chain PROM split für shared 70B |

---

## FEHLER-MUSTER (P-001 bis P-012)

| ID | Problem | Lösung |
|----|---------|--------|
| P-001 | KAS/PROM Verwechslung | grep -n "MIN_STAKE" vor Commit |
| P-002 | ssc ohne --testnet Flag | ssc compile --testnet --network testnet-10 |
| P-003 | std::sync::Mutex in async | tokio::sync::Mutex |
| P-004 | Groth16 Parameter-Mismatch | kaspa-zk-params Crate |
| P-005 | CIDv0 statt CIDv1 | ipfs add --cid-version 1 |
| P-006 | float64 Vergleiche | epsilon: abs(a-b) < 0.001 |
| P-007 | libp2p NAT-Problem | STUN/TURN einrichten |
| P-008 | Datei nicht auf Disk | grep verifizieren VOR Commit |
| P-009 | yara C-Dependency | Custom Matcher, yara-x für Production |
| P-010 | Unnötige Mutex | Arc<T> statt Arc<Mutex<T>> bei &self |
| P-011 | Heuristische Confidence | LLM-Confidence für Production |
| P-012 | Guardian Centralization | Hybrid routing + Ensemble voting |

---

## DESIGN-SYSTEM

| Variable | Wert | Verwendung |
|----------|------|-----------|
| --void | #050505 | Haupthintergrund |
| --mint | #00E5A0 | Primärer Akzent |
| --mint-dim | #00B880 | Sekundärer Mint |
| --silver | #C8C8C8 | Haupttext |
| --silver-dim | #787878 | Sekundärtext |
| --gold | #C8A060 | Timestamps, Labels |
| Font Display | Space Mono (700) | Wordmark, Labels |
| Font Body | Space Grotesk (300/400) | Fließtext |

---

## TIMELINE

| Monat | Meilenstein |
|-------|-----------|
| Mai 2026 | Contracts live, first PROM, DEX pool |
| Juni 2026 | ZK-proof real, P2P, Phi-3, LLaMA fine-tuned |
| Juli 2026 | Desktop client beta |
| August 2026 | Full desktop release + Guardian installer |
| September 2026 | iOS + Android mobile clients |
| Q4 2026 | vProgs integration |

---

## FAQ-BANK

### Q: Wie funktioniert das Zwei-Token-Modell?
KAS = wirtschaftliche Kaution (Slashing bei Betrug).
PROM = Belohnung für Sicherheitsarbeit (nie kaufbar, nur verdient).

### Q: Wie kommt PROM in den Markt?
Tag 1: Erste PROM bei erster akzeptierter Regel. KAS/PROM Pool auf Kasplex DEX.
Kein ICO. Deflation -10%/Jahr.

### Q: Werden Regeln automatisch bestätigt?
Nein — 4 Stufen: KI-Filter (85%) → 5 Meldungen → Validator-Vote (67%) → 24h Challenge.

### Q: False Positive?
Auto-Tuning erhöht Schwellenwert. Guardian verliert 50% Reputation. Kein Mensch nötig.

### Q: Mining bei PROM?
Leistungsbasierte Emission. Guardians = "Miner" (KI statt GPU).

---

## PENDING FAQ (noch offen)
- Föderiertes Lernen für Endnutzer?
- Guardian offline — was passiert?
- PROM auf Börsen?
- ZK-Proof Privatsphäre?
- Prometheus vs ClamAV/Wazuh?

---

### Pre-Hardfork Audit (2026-04-02)
- Full 7-level audit completed (35 checks, 5 parallel agents)
- 0 CRITICAL, 2 HIGH, 2 MEDIUM, 3 LOW findings
- 203/204 tests passing, 92% audit confidence
- VERDICT: READY FOR HARDFORK — fix H-001 + H-002 before May 5

*Prometheus v4.0 · Checkpoint 2026-04-02 · Last updated: pre-hardfork audit · The fire belongs to humanity.*
