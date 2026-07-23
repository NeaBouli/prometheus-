# PROMETHEUS — SESSION CHECKPOINT
# Last updated: 2026-07-23
# Purpose: Full recovery document. If Claude (Architect) or Claude Code
# loses context, read this file first. It contains the complete project state.

---

## IDENTITÄT

| Feld | Wert |
|------|------|
| Projekt | Prometheus — Decentralized AI Threat Intelligence |
| Repo | https://github.com/NeaBouli/prometheus- |
| Branch | Canonical target `main`; product/public/status changes remain PR-only |
| Lokaler Pfad | `$REPO_ROOT` |
| Letzter grün verifizierter Produkt-/Public-Baseline | Exact main `fc6f1c9fdcfb74c4858b12ec9265ebd6cee10dfe` merges GH-107 through protected PR #108; Prometheus CI `30006654048`, Security `30006654027`, and Pages `30006653208` pass, and raw/live README/Whitepaper/Roadmap/FAQ/llms markers were verified |
| Aktueller Entwicklungs-Slice | Issue #109 on `docs/GH-109-observable-approval-closeout` reconciles GH-107 merged/exact-main evidence through the protected documentation workflow; no product behavior changes |
| Aktuelle Tooling-Baseline | Exact main `fc6f1c9fdcfb74c4858b12ec9265ebd6cee10dfe` includes GH-58 durable ingress, GH-63's active-KIP-16-aligned verifier, GH-69 manifest preflight, GH-74 hash-only analyzer adapter, GH-77 batch isolation, GH-86 observable validators, GH-90 `file_sha256`, GH-94 mandatory-review `byte_pattern`, GH-100 pre-readiness signal registration, GH-98 public/license reconciliation, GH-103 bounded review-required Linux ELF `api_import` derivation, and GH-107 local canonical Observable Approval verification. Public/multi-host operation, trusted membership/key assignment, Sybil resistance, approved production proof artifacts, privacy-reviewed promotion/actionable analysis, durable approval consumption/authority policy, and on-chain attestation remain open. Execution artifacts remain bound to `205e1ca`; GH-9 remains ready for explicitly approved external signing. |
| Aktueller HEAD | Branch base and latest verified product/public baseline are exact main `fc6f1c9fdcfb74c4858b12ec9265ebd6cee10dfe`; mit `git log --oneline -1` prüfen |
| Rollback-Tag | `pre-session-20260413` → `6347b85` |
| Whitepaper | WHITEPAPER.md (root) + whitepaper.html (styled); miner companion, reward boundaries, GH-36/GH-39 trust boundaries, and GH-48/GH-52/GH-55/GH-58/GH-63/GH-74/GH-94/GH-107 merged boundaries remain synchronized |
| Status | Rollout-capable core remains estimated at 78-82%. GH-107 authenticates a local approval statement only and does not change rollout readiness. Durable one-time approval consumption, authority/policy management, external provenance/privacy promotion, post-Toccata canary execution, approved v2 proof artifacts, actionable analysis, and full rollout evidence remain gated. |
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
- GH-9 Software-Handoff gemergt: PR #11 landete als `6213c559`; `full` bleibt das sieben-Fixture-Profil mit öffentlichem Metrics-Oracle-Key, während `testnet-10-validator-staking-h001` genau einen H-001-Canary auf dem TLS-only Resolver ohne Oracle-Key isoliert. Canary-Status ist durchgehend non-promotable; Prometheus CI `29412667386`, Security Audit `29412667410`, Pages `29412666483` und die Live-Whitepaper-Prüfung bestehen für den Merge.
- Issue #9 reaktiviert: öffentlicher TN10 P2PK-Outpoint `24e81339f3656689643ca86e3c53c4c5336e4273bb127d25bdaf328e5da241c7:0`, `100100000000` Sompi, passende Adresse/x-only Public Key und non-coinbase/unspent Status sind offiziell bestätigt. Der exact-main schema-v2 Request/Digest ist deterministisch gebaut und live preflight-verifiziert. Offen bleiben externe BIP340-Signatur, vollständige Operator-Verifikation, One-shot-Broadcast, Bestätigung, `operator_record`-Receipt-Erfassung/-Verifikation und unabhängige Chain-Evidence. Danach bleiben sechs State-Contracts, Metrics-Oracle-Transaktion und Release-Hardening für den vollständigen Rollout offen.
- GH-17 abgeschlossen: PR #18 landete als `9477fab`; Signing-Request Schema v2 bindet die finale 66-Byte-Schnorr-Shape, alle Mass-Dimensionen sowie pinned Relay-/Overall-Fee-Floors. 35 Operator-Tests, CodeRabbit, exact-main CI/Security/Pages und der reale funding-bound Preflight sind grün.
- GH-13 abgeschlossen: PR #14 wurde normal als `2e4b4ec` gemergt. Der experimentelle opt-in Miner Companion bietet strict TOML, credential-freies loopback Testnet-10 wRPC, standardmäßig keinen Remote-Netzwerkzugriff im Preflight und einen fehlertoleranten DAG-Healthloop. Kein Stratum/Firmware-Zugriff, keine Host-Scans, Reports, Rewards, Validator- oder Honeypot-Rolle. 153 Workspace-Tests, lokale Security-/Docs-Gates, alle PR-Kontexte sowie exakte Merge-Commit-CI/Security/Pages und die Live-Whitepaper-Prüfung bestehen.

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
2. git log --oneline -5              → aktuellen HEAD prüfen; letzter dokumentierter grün verifizierter Produkt-/Tooling-Commit = d0f78a9
3. git tag -l                        → Rollback: pre-session-20260413
4. cargo test 2>&1 | tail -5         → Muss grün sein
5. Lies BACKLOG.md                   → Priorisierte Task-Liste
6. Lies memory/AUDIT.md ab Zeile 337 → Pre-Hardfork Findings
7. Lies memory/ERRORS.md             → 12 bekannte Patterns
```

**Status: Feature-complete through Sprint 7. Kaspa Toccata and all seven current-Silverc compile/ABI/runtime gates pass locally and in CI. GH-7 is merged and the live read-only testnet-10 resolver probe passes. GH-9's closed, manifest-bound H-001 canary profile omits the unrelated oracle key and cannot promote full readiness; its public funding/identity and deterministic schema-v2 request/digest were rebuilt from exact main `205e1ca`, live-preflight revalidated, and remained byte-identical across two builds and to the prior baseline. The remaining canary gates are an explicitly approved external BIP340 signature, complete operator verification, separately approved one-shot broadcast, confirmation, receipt, and independent evidence. GH-25 is merged and exact-main verified at `072f04a` with the keyless value-preserving `reportMetrics` transition, separate P2PK fee sponsor, two external signatures, complete input execution, live UTXO revalidation, acknowledged journaled broadcast, and successor observation; real operation remains. GH-13 remains accepted at `2e4b4ec` as a development-only local Testnet-10 wRPC observer. Full rollout still requires all seven release fixtures, six state-contract deployments, real oracle/sponsor inputs/signatures/evidence, and exact-commit release hardening.**

**Offene Tasks (priorisiert):**
- [x] PATTERN-010 fix: Arc<Phi3Model> statt Arc<Mutex<Phi3Model>> — DONE `6347b85`
- [x] Rust client production/beta stub gates — DONE 2026-07-08 (`PROMETHEUS_RUNTIME`)
- [~] H-001: LE encoding Verifikation — repo `silverc` fixture passes for Rust byte vectors; all six current state fixtures compile and their runtime gates pass; release/handoff/evidence tooling, keyless genesis, and keyless value-preserving reportMetrics assembly/dual-signature verification/guarded broadcast/observation pass exact-main checks; real signatures, receipts, and independent evidence remain
- [~] Sprint 9: H-001 canary handoff is rebuilt from exact main `205e1ca`, live-preflight verified, byte-identical, and non-promotable; real signature/receipt/evidence execution remains external. The keyless metrics transition operator is merged/exact-main verified; real oracle/sponsor UTXOs, signatures, confirmation/evidence, remaining state contracts, and exact-commit release hardening still block full rollout
- [x] GH-1 covenant-genesis capability gate — merged via PR #2 as `9d74c0c`; transaction version 1, compiled-script P2SH, official funding-outpoint/unbound-output covenant-ID derivation, and funding-input binding after ID derivation are required; four tamper classes reject; main CI, Security Audit, and Pages pass
- [x] Sprint 10B hybrid routing software: PR #34 merged/exact-main verified as `ce1d213`; 8B first, exact 70B escalation below `0.70`, fail-closed safety envelope, and unchanged `0.85` submission threshold; live model wiring/calibration remains
- [~] Sprint 10B ensemble voting: GH-36/39 plus merged/exact-main GH-42/GH-44/GH-48/GH-52 are implemented. Real two-host operation, broad discovery, trusted membership/key assignment, Sybil resistance, and on-chain attestation remain
- [~] Q-003: fp_rate Oracle — current-Silverc contract gate, public report/request/result/evidence/status gates, and repository-owned value-preserving two-input Rust assembly, dual external-signature verification, guarded broadcast, and successor observation are merged and exact-main verified at `072f04a`; real inputs/signatures/confirmation/evidence remain
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
10. Current Silverc tooling, contract compatibility, LE/signed-int bounds, and closed deployment profiles must remain CI-gated through Sprint 9
11. Jede neue HTML-Seite: SEO/GEO-Checkliste (Schema.org, OG, ai-summary)
12. Mobile Hamburger-Menü auf jeder Seite
13. GitHub-only Contact (kein Email, kein Discord DM)

---

## ARCHITEKTUR-ENTSCHEIDUNGEN (#1-18)

| # | Entscheidung |
|---|-------------|
| 1 | KAS = Staking-Asset der Validators |
| 2 | PROM = earned-only Reward/Governance; kanonische Guardian-Reputation bleibt separater Kaspa-L1-State |
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

## FEHLER-MUSTER (P-001 bis P-013)

| ID | Problem | Lösung |
|----|---------|--------|
| P-001 | KAS/PROM Verwechslung | grep -n "MIN_STAKE" vor Commit |
| P-002 | Obsoleten `ssc`-Compile/Deploy-Pfad verwenden | Pinned `silverc`-Release-Build plus keyless Repository-Operator verwenden |
| P-003 | std::sync::Mutex in async | tokio::sync::Mutex |
| P-004 | Groth16 Relation/VK-Mismatch | Manifest SHA-256 pinning, exact KIP-16 serialization, independent relation-source/VK/vector approval |
| P-005 | CIDv0 statt CIDv1 | ipfs add --cid-version 1 |
| P-006 | float64 Vergleiche | epsilon: abs(a-b) < 0.001 |
| P-007 | libp2p NAT-Problem | STUN/TURN einrichten |
| P-008 | Datei nicht auf Disk | grep verifizieren VOR Commit |
| P-009 | yara C-Dependency | Custom Matcher, yara-x für Production |
| P-010 | Unnötige Mutex | Arc<T> statt Arc<Mutex<T>> bei &self |
| P-011 | Heuristische Confidence | LLM-Confidence für Production |
| P-012 | Guardian Centralization | Hybrid routing + Ensemble voting |
| P-013 | Canary als Full Rollout ausgeben | Nur geschlossene manifestgebundene Profile und non-promotable Canary-Status verwenden |

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

## READINESS-GATED SEQUENCE

| Gate | Milestone |
|------|-----------|
| Current | GH-9 H-001 testnet-10 canary external signature, broadcast, receipt, and independent evidence |
| Core rollout | Remaining state deployments, real metrics transition, reviewed observable extractors/privacy gates, separate v2 wire and statement/relation, approved proof artifacts, privacy-preserving pairing/channel, PROM emission, operated multi-host network |
| Client rollout | Production AI, rule distribution, desktop installer, and security evidence |
| Mobile rollout | Platform-specific Flutter implementation and review after core/client readiness |
| Future research | vProgs integration under a separately reviewed protocol |

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

- VERDICT update 2026-07-16: GH-25 closes the repository-side metrics transaction assembly gap with a value-preserving two-input Toccata-v1 transition, separate P2PK fee sponsor, two external `SIG_HASH_ALL` BIP340 signatures, exact source/state/request/fee/mass binding, full covenant and P2PK execution, live UTXO revalidation, collision-safe outputs, acknowledged crash-consistent broadcast, and successor observation. Forty-nine deployer tests, full workspace fmt/clippy/tests, 55 pinned upstream Silverc tests, independent Terra review, PR #26, exact-main Prometheus CI `29453756167`, Security Audit `29453756135`, Pages `29453755086`, and live Whitepaper verification pass for `072f04a`. Real inputs, signatures, confirmation, successor evidence, and exact-rollout release evidence remain.

*Prometheus v4.0 · Checkpoint 2026-07-16 · Last updated: operational main `b14d36fc` exact-main CI/Security/Pages green with merged GH-48 strict Guardian/relay roles, owner-only submission, bounded JSON health, graceful drain, and separate-process same-host relay evidence while public/multi-host operation remains open + GH-44 owner-only persistent transport identity, strict routes, bounded relay service, health events, and isolated three-node relay/AutoNAT/DCUtR-fallback/disconnect evidence merged/exact-main/live verified + GH-36 local fail-closed 5+ complete-ballot gate merged + GH-39 per-session BIP340 intake and persistent replay/equivocation protection merged + GH-42 bounded cancellation-safe direct QUIC ballot carrier and owner-only collector bridge merged/exact-main/live verified + GH-30 bounded required-check runtimes and pinned audit environment complete + H-001 handoff rebuilt/live-preflight verified from exact execution baseline `205e1ca` with byte-identical schema-v2 request + GH-25 keyless value-preserving reportMetrics operator merged/exact-main green at `072f04a` + external signatures/broadcast/evidence pending + GH-13 experimental local miner companion accepted at `2e4b4ec` + seven current-Silverc runtime gates + crash-consistent keyless Toccata-v1 genesis operator + manifest-bound non-promotable H-001 testnet-10 profile + TLS-only official resolver probe + public receipts/evidence/status staging + exact-commit release-hardening gates · The fire belongs to humanity.*

## Checkpoint 2026-07-23: GH-58 exact-main verified

- Issue #58 is closed after PR #60 merged normally as `22bc55a72bf441a2abc0372bc0eb789fb89fbb0b`.
- Exact-main Prometheus CI `29962533693`, Security Audit `29962533720`, and Pages `29962533075` passed, including Rust/Python tests, formatting/linting, SilverScript and current-Silverc runtime gates, package checks, dependency audits, Gitleaks, Pages build, and deployment.
- The owner-only ThreatHint verifier IPC, trusted network/domain binding, persistent monotonic freshness/replay admission, atomic durable analyzer outbox, and shutdown-safe worker accounting are merged. Production acceptance remains fail-closed until an independently approved real Groth16/KIP-16 relation, verifying key, and vectors plus an explicit analyzer-domain adapter exist.
- Scope-weighted estimates are core 76-80%, complete vision 42-47%, and 53-58% remaining. H-001 execution, remaining deployments, real metrics transition, two-host Guardian evidence, production verifier/analyzer wiring, PROM emission, and production nodes remain open.
- No wallet, private key, secret, signature, raw transaction, broadcast, contract, reputation, KAS/PROM, slash ACL, commit-reveal formula, emergency-stop policy, or foreign untracked file was accessed or changed. `Prometheus-1.png` remains untouched and uncommitted.

## Checkpoint 2026-07-23: GH-63 merged and exact-main verified

- Active KIP-16 and pinned `rusty-kaspa` v2.0.1 provide the upstream BN254/Arkworks serialization baseline; the old `kaspa-zk-params` assumption is retired.
- `prometheus-threat-proof` performs real manifest-pinned Groth16 verification with exact canonical VK/proof parsing and complete domain/network/ThreatHint statement binding.
- The Guardian adapter/service uses owner-only exact-schema configuration, fixed no-shell invocation, clean environment, hard timeout, and distinct valid/invalid/syntax/unavailable exits.
- No production relation, VK, proving key, or independently approved vectors are invented or bundled. Default operation remains fail-closed `busy`; accepted production analysis is not claimed.
- Local verification passes 247 workspace Rust tests/2 live ignores, 144 Guardian tests/3 live-model skips, 7 focused Rust verifier tests, 18 focused Python adapter/service tests, locked optimized builds, all three Cargo packages, formatting/lint, Memory/HTML/workflow checks, and dependency audit. CodeRabbit's valid ancestor-owner hardening is implemented, all protected PR contexts passed, and exact-main Prometheus CI `29968203074`, Security `29968203053`, and Pages `29968202562` are green for `f4f9df9`.
- Scope-weighted estimates are core 77-81%, complete vision 43-48%, and 52-57% remaining.

## Checkpoint 2026-07-23: GH-74 analyzer adapter merged

- Issue #74 and merged PR #75 implement the explicit bounded mapping from GH-58 durable outbox jobs into a frozen verified-v1 analyzer type.
- Digest, canonical wire, trusted network, real proof mode, and original admission time are revalidated. ThreatHint v1 carries no concrete IOC strings, so the analyzer emits only confidence `0.0`, no YARA rule, and no submission without invoking LLM or YARA generation.
- Per-instance drains are serialized and capped at 32; delivery follows only an exact safe result. Parse/network/analyzer/result/clock failures remain pending.
- Local evidence is 24 focused tests, 158 complete Guardian passes with three intentional live-model skips, Black, Ruff, and focused Pylint 10.00/10. PR #75 passed all ten protected contexts twice with no open review thread and merged normally as `17d8ceb`; exact-main Prometheus CI `29973290911`, Security Audit `29973290913`, and Pages `29973290610` pass.
- Scope-weighted estimates are core 78-82%, complete vision 44-49%, and 51-56% remaining. Production proof artifacts, a concrete-observable channel or future schema, real actionable analysis, and all existing external rollout gates remain open.
