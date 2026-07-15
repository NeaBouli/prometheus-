# PROMETHEUS — SESSION CHECKPOINT
# Last updated: 2026-07-15
# Purpose: Full recovery document. If Claude (Architect) or Claude Code
# loses context, read this file first. It contains the complete project state.

---

## IDENTITÄT

| Feld | Wert |
|------|------|
| Projekt | Prometheus — Decentralized AI Threat Intelligence |
| Repo | https://github.com/NeaBouli/prometheus- |
| Branch | `docs/GH-7-closeout` from merged baseline `288ea18` |
| Lokaler Pfad | /Users/gio/Desktop/repos/prometheus |
| Letzter grün verifizierter Produkt-/Tooling-Commit | `4176093` — GH-4 closeout baseline; main CI `29406057800`, Security `29406057729`, Pages `29406056965` green |
| Aktuelle Tooling-Baseline | GH-7 TLS-only official public resolver plus funding-free testnet-10 node/Toccata probe merged as `288ea18`; 30 Rust tests and main CI/Security/Pages pass |
| Aktueller HEAD | Mit `git log --oneline -1` prüfen; Bridge-/Status-Commits können neuer sein |
| Rollback-Tag | `pre-session-20260413` → `6347b85` |
| Whitepaper | WHITEPAPER.md (root) + whitepaper.html (styled), status refreshed and verified 2026-07-11 |
| Status | Feature-complete through Sprint 7. Post-Toccata deployment verification active. |
| GitHub Pages | https://neabouli.github.io/prometheus-/ |
| Google Search Console | Verified: googleaa2902079481c7a8 |

---

## ROLLEN

| Rolle | Wer | Aufgabe |
|-------|-----|---------|
| Core Dev | NeaBouli | Triggert Tasks, entscheidet über Sprints |
| Architect / Auditor | Claude (claude.ai) | Architektur, Audit, Antworten auf QUESTION FOR CLAUDE |
| Implementierung | Claude Code | Schreibt Code, Tests, Commits, Pushes |
| Codex Hauptagent | GPT-5.6 Sol | Architektur, Security, Integration, vollständige Verifikation und PR-Verantwortung |
| Codex Worker | `spark_worker` | Kleine klar begrenzte Low-Risk-Patches; Sol prüft jeden Diff |
| Codex Analyse | `terra_analyst` | Read-only Repository-/Dokumentations-/Log-Audits |

## GH-4 KEYLESS GENESIS OPERATOR

- `modules/silverc-deployer` baut Kaspa transaction v1 mit Compute-Budget 10 und exakter kontextueller `storage_mass`.
- Covenant-ID wird aus Funding-Outpoint und ungebundenem Genesis-Output abgeleitet; Binding folgt erst danach.
- Der exakte live unspent Funding-UTXO wird im Preflight und unmittelbar vor Broadcast geprüft.
- Nur der 32-Byte-`SIG_HASH_ALL`-Digest verlässt den Repository-Operator; ein externer Vault/HSM liefert die öffentliche BIP340-Signaturantwort.
- Fee-Minimum/-Maximum, Netzwerk, P2PK-Funding, P2SH-Contract, Request-Hash, vollständige Signatur und Transaktion werden fail-closed validiert.
- 27 gemergte GH-4 Tests enthalten feste öffentliche Transaction-/Covenant-/Sighash-/Request-/Storage-Mass-Werte, Secret-/Recovery-Gates und einen dateibasierten Python-Request/Rust-Signatur-Handoff; das gemergte GH-7 erweitert auf 30 Tests mit Resolver- und aufgelöster-TLS-Endpoint-Fail-Closed-Coverage.
- Offizielles PSKT/PSKB bleibt ausgeschlossen, solange dessen v1-Inputpfad Sigop- statt Compute-Budget-Commitments erzeugt. Pinned v2.0.1 unterstützt testnet-10, nicht testnet-12.
- Lokal grün: Rust fmt/clippy/tests; frischer sieben-Contract Silverc-Release-Build; Python deploy preflight, request builder/verifier, operator procedure und external capability verifier.
- GH-7 gemergt: `kaspa-resolver://public` ist TLS-only und testnet-10-only; der funding-freie Probe bestätigt einen synchronisierten, UTXO-indexierten `rusty-kaspa 2.0.1` Node über Toccata-DAA. Main CI/Security/Pages sind grün.
- Offen in Issue #9: real finanzierter testnet-10-Run, externe Signaturen, bestätigte `operator_record` Receipts, unabhängige Chain-Evidence, Metrics-Oracle-Transaktion und Release-Hardening für den exakten Rollout-Commit.

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
- [x] GitHub Pages aktiv/live: latest pages-build-deployment succeeded for `a11545b`
- [ ] Repository public schalten
- [ ] Gitcoin Grants Antrag einreichen (Deadline: April 2026)
- [ ] Discord/Telegram aufbauen
- [ ] Apple Developer Account + Google Play Account (vor Sprint 13)

### Für Claude Code (nächste Session):

**STARTFLOW — Lies dies zuerst:**
```
1. cd /Users/gio/Desktop/repos/prometheus
2. git log --oneline -5              → aktuellen HEAD prüfen; letzter dokumentierter grün verifizierter Produkt-/Tooling-Commit = ea67b93
3. git tag -l                        → Rollback: pre-session-20260413
4. cargo test 2>&1 | tail -5         → Muss grün sein
5. Lies BACKLOG.md                   → Priorisierte Task-Liste
6. Lies memory/AUDIT.md ab Zeile 337 → Pre-Hardfork Findings
7. Lies memory/ERRORS.md             → 12 bekannte Patterns
```

**Status: Feature-complete through Sprint 7. Kaspa Toccata status researched 2026-07-07; all seven current-Silverc compile/ABI/runtime gates and signed-int deployment bounds pass locally and in CI. The deterministic release archive, deploy preflight/requests/procedure, merged repository-owned keyless transaction-v1 genesis operator, receipt/evidence/status staging, operator handoff, release-readiness audit, metrics-oracle handoff, and exact-commit release-hardening gates are implemented. The genesis operator uses compute budget 10, exact contextual `storage_mass`, official covenant-ID derivation, exact live funding-UTXO checks, external digest-only BIP340 signing, full verification, an exclusive crash-recovery journal, transaction-ID reconciliation, 20-second wRPC deadlines, and source-bound covenant-output observation. GH-7 is merged as `288ea18`; all 30 operator tests, the seven-contract integration, main CI/Security/Pages, and the successful live read-only testnet-10 resolver probe pass. Issue #9 now tracks the real funded testnet-10 signatures and confirmed receipts, independent public node/explorer evidence, the external signed metrics-oracle transaction, and release-hardening evidence for the exact rollout commit.**

**Offene Tasks (priorisiert):**
- [x] PATTERN-010 fix: Arc<Phi3Model> statt Arc<Mutex<Phi3Model>> — DONE `6347b85`
- [x] Rust client production/beta stub gates — DONE 2026-07-08 (`PROMETHEUS_RUNTIME`)
- [~] H-001: LE encoding Verifikation — repo `silverc` fixture passes for Rust byte vectors; ValidatorStakingState commit/reveal/slash/request-withdraw/complete-withdraw runtime gates pass; signed-int deployment bounds enforced as `0..=i64::MAX`; GuardianReputationState/RuleStorageState/CommunityDonationsState/DevIncentivePoolState/GovernanceAutoTuningState compile/ABI/runtime gates pass locally; current-Silverc release-bundle manifest/archive, deploy preflight, operator runbook, external deploy request set/verifier, public deploy operator procedure, public orchestrator-result receipt import with raw-transaction rejection, deployment receipt verifier, public receipt-evidence verifier, deployment status staging, operator handoff package, release-readiness audit, public metrics-oracle report preflight, unsigned oracle tx-request builder, external oracle operator procedure, public external-operator capability verifier, public oracle tx-result verifier, public oracle tx-evidence verifier, public oracle status-draft staging, and public release-hardening evidence verification pass locally
- [ ] Sprint 9: Contracts compile + deploy — the merged repository-owned keyless genesis tooling passes local/main CI; blocked until funded testnet-10 signatures and confirmed receipts, independent public node/explorer evidence, the external signed metrics-oracle operation, and exact-commit release-hardening evidence pass
- [x] GH-1 covenant-genesis capability gate — merged via PR #2 as `9d74c0c`; transaction version 1, compiled-script P2SH, official funding-outpoint/unbound-output covenant-ID derivation, and funding-input binding after ID derivation are required; four tamper classes reject; main CI, Security Audit, and Pages pass
- [ ] Sprint 10B: Guardian hybrid routing (8B/70B) + Ensemble voting
- [~] Q-003: fp_rate Oracle — current-Silverc contract gate uses signed metrics input; public report preflight, unsigned tx-request builder, external oracle operator procedure, public external-operator capability verifier, public tx-result verifier, public tx-evidence verifier, and public status-draft staging are locally covered; external transaction assembly/signing/broadcast/deploy operation pending
- [ ] Sybil resistance final design — Architect decision needed
- [ ] M-001: yara_generator.py Heuristic → LLM confidence
- [ ] M-002: Performance test threshold relaxen oder --release gate
- [ ] PLONK evaluation for Light Client ZK-proofs

### Wartet auf externe Events:
- [~] ssc/Silverscript tooling local install + smoke test → upstream `silverc`, all seven current-Silverc runtime gates, release archive, deploy preflight/requests/procedure, merged repository-owned keyless genesis operator, receipts/evidence/status staging, metrics-oracle handoff, and release-hardening verification pass locally and in CI; funded testnet-10 signing/confirmation/evidence pending
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
9. Legacy-Tests nutzen kaspa-testnet-10; post-Toccata Deployment braucht TN12/Toccata-Tooling-Verifikation
10. Current Silverscript tooling and actual Prometheus contract compatibility must be tested post-Toccata before Sprint 9
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
- VERDICT update 2026-07-12: H-002 fixed; upstream `silverc`, repo H-001 fixture, current-silverc `ValidatorStakingState.sil` compile/ABI gate, `commitVote`/`revealVote`/`slashInvalidReveal`/`requestWithdraw`/`completeWithdraw` runtime tests, signed-int deployment-bound guards, GuardianReputationState compile/ABI/runtime/formula gates, RuleStorageState compile/ABI/runtime gates, CommunityDonationsState compile/ABI/runtime gates, DevIncentivePoolState compile/ABI/runtime gates, GovernanceAutoTuningState signed-metrics/auto-tune runtime gates, all-fixture release-bundle manifest/archive/deploy preflight, operator runbook, external deploy request set/verifier, public deploy operator procedure, public orchestrator-result receipt import with raw-transaction rejection, deployment receipt verifier, public receipt-evidence verifier, deployment status staging, release-readiness audit, public metrics-oracle report preflight, unsigned metrics-oracle tx-request builder, external oracle operator procedure, public external-operator capability verifier, public oracle tx-result verifier, public oracle tx-evidence verifier, public oracle status-draft staging, and public release-hardening evidence verification passed locally; approved network deploy/orchestration tooling, real public deploy results/receipts plus public node/explorer evidence, external signed metrics-oracle transaction assembly/signing/broadcast/deploy operation, and public release-hardening evidence for the exact rollout commit remain deploy blockers before Sprint 9.

- VERDICT update 2026-07-15: H-002 is fixed; all seven current-Silverc compile/ABI/runtime gates, signed-int deployment guards, deterministic release handoff, and the merged repository-owned keyless Toccata-v1 genesis operator pass locally and in main CI. Exact contextual storage mass, compute budget 10, covenant derivation/binding, dual live-UTXO validation, digest-only external signing, full verification, fee bounds, exclusive intent journaling, retry reconciliation, RPC deadlines, and source-bound observation are covered by 27 tests plus a seven-contract integration. Funded testnet-10 signatures/receipts, independent chain evidence, the external metrics-oracle transaction, and exact-commit release evidence remain Sprint 9 blockers.

*Prometheus v4.0 · Checkpoint 2026-07-15 · Last updated: seven current-Silverc runtime gates + deterministic release handoff + crash-consistent keyless Toccata-v1 genesis operator + 30 local unit/security tests + TLS-only official testnet-10 resolver probe + seven-contract integration + public receipts/evidence/status staging + metrics-oracle handoff + exact-commit release-hardening gates · The fire belongs to humanity.*
