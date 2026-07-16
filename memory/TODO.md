# PROMETHEUS – TASK QUEUE
# Format: - [ ] [PRIO] Beschreibung | Verantwortlich | Dependencies
# PRIO: P0=Kritisch, P1=Hoch, P2=Mittel, P3=Niedrig
# Status: [ ]=offen, [~]=in Arbeit, [x]=erledigt, [!]=blockiert
# Last Updated: 2026-07-16

---

## ═══ SPRINT 0: SETUP & TESTNET (Woche 1) ═══

- [x] [P0] Repo-Struktur auf GitHub anlegen (memory/, modules/, scripts/, .gitignore) | Claude Code | 2026-03-21
- [x] [P0] Alle memory/-Dateien initial befüllen und pushen | Claude Code | 2026-03-21; laufende Integritäts-/Bridge-Pflege ist in CI und Workflow verankert
- [x] [P0] Kaspa Testnet-10-Node installieren und starten (rusty-kaspa v1.1.0) | Claude Code | 2026-03-21
- [x] [P0] Verbindung zum Testnet verifizieren (8 Peers, IBD active) | Claude Code | 2026-03-21
- [x] [P0] Silverscript Compiler/Tooling installieren und testen | Claude Code | Pinned upstream `silverc`, H-001/all seven compile/ABI/runtime gates, signed-int bounds, deterministic release archive, request/procedure verification, keyless genesis/reportMetrics operators, receipts/evidence/status and release-hardening gates pass; real signatures/deployments are tracked separately as rollout execution
- [x] [P0] GH-1 offiziellen SilverScript Covenant-Genesis-Mechanikvertrag im externen Operator-Gate erzwingen | Codex | Merged via PR #2 as `9d74c0c`; main CI, Security Audit, and Pages pass for transaction v1, compiled-script P2SH, official covenant-ID derivation, and post-derivation funding-input binding
- [x] [P0] GH-4 keyless Toccata-v1 SilverScript Genesis Operator | Codex | Merged via PR #5 as `ea67b93`; exact v1 contextual storage mass, compute budget 10, covenant ID, live UTXO checks, external BIP340 verification, fee caps, exclusive intent journal, retry reconciliation, RPC deadlines, source-bound observation, 27 tests, main CI/Security/Pages all pass
- [x] [P0] GH-7 official public-resolver mode + funding-free testnet-10 probe | Codex | PR #8 merged as `288ea18`; main CI `29408432584`, Security `29408432511`, and Pages `29408431512` pass
- [x] [P0] GH-17 Genesis-Operator Signed-Shape Fee/Mass-Härtung | Codex | PR #18 merged as `9477fab`; exact-main CI/Security/Pages green; schema-v2 request rebuilt deterministically
- [x] [P0] GH-9 kanonischen Public-Signature-Import härten | Codex | PR #23 merged as `f79150d`; 38 focused tests, independent review, exact-main CI/Security/Pages, and live Whitepaper pass
- [x] [P0] GH-25 keyless GovernanceAutoTuning `reportMetrics` operator | Codex | Two-input value-preserving Rust transition, separate P2PK fee sponsor, dual external BIP340 verification, complete input execution, live UTXO checks, acknowledged journaled broadcast, successor observation, 49 deployer tests, independent review, PR #26, exact-main CI/Security/Pages, and live Whitepaper pass at `072f04a`; real chain operation/evidence continues under rollout execution gates
- [x] [P0] GH-9 H-001 handoff von aktuellem exact main neu bauen | Codex | `205e1ca` CI/Security/Pages green; seven-artifact canary handoff rebuilt, live UTXO revalidated, two prepares byte-identical to prior baseline, owner-only modes and full-directory Gitleaks pass; external signature/broadcast/evidence remain
- [x] [P0] GH-30 Required-Check-Laufzeiten begrenzen und Audit-Toolchains pinnen | Codex | PR #31 merged as `71e5783`; alle neun geschützten Kontextnamen unverändert; exact-main CI `29457601210`, Security `29457601183`, Pages `29457600490` green
- [!] [P0] GH-9 `ValidatorStakingH001` Canary auf testnet-10 ausführen | Codex + externer Signer | Funding/identity and exact-main `205e1ca` schema-v2 request/digest live-revalidated and byte-identical; explicit external BIP340 response, operator verification, one-shot broadcast, confirmation, receipt, and independent evidence remain
- [x] [P0] rusty-kaspa als Dependency in Cargo.toml einbinden | Claude Code | 2026-03-21; pinned to v2.0.1 on 2026-07-07
- [x] [P0] autodidactic.py vollständig testen (alle Memory-Operationen) | Codex | 2026-07-12; stdlib regression suite covers memory loading, next-task priority/dependency selection, in-progress completion, padded STATUS row replacement, and blocker detection; wired into Prometheus CI Memory Integrity job
- [x] [P0] .gitignore konfigurieren (.secrets/, /tmp/, target/, __pycache__) | Claude Code | 2026-03-21
- [x] [P0] GitHub Actions CI/CD Grundkonfiguration (build + test) | Claude Code | 2026-03-21 (ci.yml aus Setup)

---

## ═══ SPRINT 1: CORE CONTRACTS (Woche 2-3) ═══

- [x] [P1] ValidatorStaking.ss schreiben (register, commitVote, revealVote, slash) | Claude Code | 2026-03-21 (11 tests)
- [x] [P1] GuardianReputation.ss schreiben (register, submitContribution, votingPower) | Claude Code | 2026-03-21 (9 tests); current-Silverc GuardianReputationState compile/ABI/runtime/formula gates added 2026-07-09
- [x] [P1] GovernanceAutoTuning.ss schreiben (auto_tune, alle Parameter) | Claude Code | 2026-03-21 (8 tests, legacy fp_rate stub); current-Silverc GovernanceAutoTuningState runtime gates added 2026-07-11 with signed metrics `fp_rate` input
- [x] [P1] DevIncentivePool.ss schreiben (proposeGrant, vote, payGrant, recommended_reward) | Claude Code | 2026-03-21 (9 tests); current-Silverc DevIncentivePoolState compile/ABI/runtime gates added 2026-07-11
- [x] [P1] CommunityDonations.ss schreiben (donateKas, getDonations) | Claude Code | 2026-03-21 (8 tests); current-Silverc CommunityDonationsState compile/ABI/runtime gates added 2026-07-11
- [x] [P1] RuleStorage.ss schreiben (storeRule als KRC20-Asset) | Claude Code | 2026-03-21 (9 tests); current-Silverc RuleStorageState compile/ABI/runtime gates added 2026-07-11
- [x] [P1] Unit-Tests für ValidatorStaking (min. 10 Tests) | Claude Code | 2026-03-21 (11 tests)
- [x] [P1] Unit-Tests für GuardianReputation (min. 8 Tests) | Claude Code | 2026-03-21 (9 tests)
- [ ] [P1] Alle Contracts auf Testnet deployen und Adressen in STATUS.md eintragen | Codex | Repository operator implemented; wartet auf echten testnet-10 Funding-Outpoint, externe Signaturen, bestaetigte operator_record Receipts plus unabhaengige Node/Explorer-Evidence, Metrics-Oracle-Transaktion und Release-Hardening-Evidence fuer den exakten Rollout-Commit
- [x] [P1] Audit-Request für alle Contracts an Claude vorbereiten | Claude Code | 2026-03-21

---

## ═══ SPRINT 2: LIGHT CLIENT BASIS (Woche 4-5) ═══

- [ ] [P1] Rust-Projekt initialisieren (cargo new prometheus-client) | Claude Code | -
- [ ] [P1] Kaspa RPC-Verbindung implementieren (connection.rs) | Claude Code | rusty-kaspa
- [ ] [P1] KRC20-Asset-Leser implementieren (krc20.rs – Regeln von Chain lesen) | Claude Code | connection.rs
- [ ] [P1] Einfacher Datei-Scanner implementieren (scanner.rs, YARA-Integration) | Claude Code | -
- [ ] [P2] Heuristische Analyse (heuristic.rs – API-Call-Monitoring) | Claude Code | scanner.rs
- [ ] [P2] Quarantäne-Management (quarantine.rs) | Claude Code | scanner.rs
- [ ] [P2] P2P-Grundgerüst (p2p.rs mit libp2p) | Claude Code | -
- [ ] [P2] ZK-Proof-Generierung (zk_proof.rs, Groth16) | Claude Code | -
- [ ] [P2] Tauri-App Grundgerüst (UI-Shell, System-Tray) | Claude Code | Rust-Client
- [ ] [P2] Integration-Tests Client ↔ Testnet | Claude Code | Alle Client-Module
- [x] [P2] GH-13 experimentellen opt-in Miner Companion als lokalen Testnet-10 wRPC Observer implementieren | Codex | PR #14 merged as 2e4b4ec; strict TOML, credential-free loopback, Development-only, scanning/reporting/rewards/validator/honeypot disabled; exact-merge CI/Security/Pages pass

---

## ═══ SPRINT 3: PHI-3-MINI INTEGRATION (Woche 5) ═══

- [ ] [P1] Phi-3-mini 3.8B herunterladen und in 4-bit quantisieren | Claude Code | -
- [ ] [P1] ONNX Runtime Wrapper implementieren (phi3.rs) | Claude Code | -
- [ ] [P1] Lokale Anomalieerkennung implementieren (detection.rs) | Claude Code | phi3.rs
- [ ] [P2] Fed-DART Gradient-Client implementieren (federated.rs) | Claude Code | phi3.rs
- [ ] [P2] Lokale Tests: Phi-3 erkennt bekannte Malware-Patterns | Claude Code | detection.rs

---

## ═══ SPRINT 4: GUARDIAN NODE (Woche 6-7) ═══

- [ ] [P1] Docker-Compose für Guardian-Node erstellen (8B + 70B Variante) | Claude Code | -
- [ ] [P1] vLLM Server für LLaMA 3 8B einrichten (llm_server.py) | Claude Code | Docker
- [ ] [P1] YARA-Regel-Generator implementieren (yara_generator.py) | Claude Code | llm_server.py
- [ ] [P1] Bedrohungsanalyse-Pipeline (analyzer.py) | Claude Code | yara_generator.py
- [ ] [P2] Reputationsberechnung (reputation/scoring.py) | Claude Code | -
- [ ] [P2] Guardian ↔ Validator Kommunikation (Proposal senden) | Claude Code | Contracts deployed
- [ ] [P2] Tests: Guardian erkennt Malware-Sample, generiert YARA-Regel | Claude Code | Alle Guardian-Module

---

## ═══ SPRINT 5: VOTING MECHANISMUS (Woche 7) ═══

- [~] [P1] Commit-Reveal vollständig in Silverscript implementieren | Claude Code | H-001 runtime fixture + ValidatorStakingState compile/ABI + commitVote/revealVote/slash/requestWithdraw/completeWithdraw runtime gates done; signed-int deployment bounds enforced; GuardianReputationState/RuleStorageState/CommunityDonationsState/DevIncentivePoolState/GovernanceAutoTuningState compile/ABI/runtime gates done locally; current-Silverc artifact smoke/release archive/deploy preflight/deploy request generation/verification and the merged repository-owned keyless genesis assembly/verification/broadcast path pass locally and in main CI; public receipts/evidence/status staging, metrics-oracle, and release-hardening gates are implemented; funded testnet-10 signatures, confirmed receipts, and independent evidence remain
- [ ] [P1] Salted Voting (30% Zufallsstichprobe) implementieren | Claude Code | Commit-Reveal
- [ ] [P1] Bond-System (10% des Stakes als Kaution) implementieren | Claude Code | Commit-Reveal
- [ ] [P2] Voting-Tests: Kollusion-Angriff scheitert | Claude Code | Voting-System

---

## ═══ SPRINT 6: END-TO-END INTEGRATION (Woche 8-9) ═══

- [ ] [P0] End-to-End-Test: Client meldet Bedrohung | Claude Code | Alle Module
- [ ] [P0] End-to-End-Test: Guardian analysiert, erstellt YARA | Claude Code | Alle Module
- [ ] [P0] End-to-End-Test: Validators stimmen ab, Konsens erreicht | Claude Code | Alle Module
- [ ] [P0] End-to-End-Test: Regel landet on-chain auf Testnet | Claude Code | Alle Module
- [ ] [P0] End-to-End-Test: Alle Clients erhalten neue Regel | Claude Code | Alle Module
- [ ] [P1] Performance-Test: Gesamtzeit < 60 Sekunden | Claude Code | E2E-Tests
- [ ] [P1] Security-Test: Sybil-Angriff scheitert | Claude Code | E2E-Tests

---

## ═══ SPRINT 7: AUDIT DASHBOARD (Woche 9) ═══

- [ ] [P2] React-App initialisieren (web/audit/) | Claude Code | -
- [ ] [P2] Live-Feed: On-Chain Events anzeigen | Claude Code | connection.rs
- [ ] [P2] Netzwerkstatistiken-Seite | Claude Code | React-App
- [ ] [P2] Dev-Grants-Transparenz-Seite | Claude Code | React-App
- [ ] [P3] Admin-Panel für Validators | Claude Code | React-App
- [ ] [P3] Admin-Panel für Guardians | Claude Code | React-App

---

## ═══ SPRINT 8: COMMUNITY & FÖRDERUNG (Parallel) ═══

- [ ] [P1] Gitcoin Grants application finalize (April 2026) | Core Dev | Sprint 7 done
- [ ] [P1] GitHub Repository öffentlich schalten | Core Dev | Sprint 6 fertig
- [x] [P2] README.md rewrite in English | Claude Code | 2026-03-22; post-Toccata deployment-gated status refreshed 2026-07-09
- [x] [P2] WHITEPAPER.md: full English whitepaper v4 in repo, with all improvements | Claude Code | 2026-03-22; current-Silverc/RuleStorage/Kasplex status refreshed 2026-07-09
- [x] [P2] CONTRIBUTING.md erstellen | Claude Code | 2026-03-22
- [x] [P2] Wiki-Grundstruktur (docs/) | Claude Code | 2026-03-22
- [x] [P2] Landing page + Wiki: use logo from /logo/Prometheus.png | Claude Code | 2026-03-22
- [ ] [P3] Discord/Telegram einrichten | Core Dev | -

---

## ═══ SPRINT 9: CONTRACTS LIVE (Mai 2026) ═══

- [x] [P0] GH-9: manifest-gebundenes H-001 testnet-10 Canary-Handoff mergen | Codex | PR #11 merged as `6213c559`; public funding recorded via PR #16 at `1e6e15c`
- [x] [P0] GH-17 Fee/Mass-Härtung vor H-001-Signatur mergen und auf Main verifizieren | Codex | PR #18 merged as `9477fab`; exact-main Prometheus CI `29442211087`, Security `29442210829`, Pages `29442209299` green
- [x] [P0] H-001 schema-v2 Request/Digest vom exact-main Commit neu bauen | Codex | Deterministic rebuild and live funding preflight pass; signing-request `6b8e6506...a5323`; no signature/broadcast
- [!] [P0] `ValidatorStakingH001` Canary real ausführen; nie als Full-/Metrics-Readiness promoten | Core Dev + externer Signer | Explicit external BIP340 response + operator verification + one-shot broadcast + confirmation + operator_record receipt capture/verification + independent evidence remain
- [!] [P0] Full-Profil: sieben Release-Fixtures auf testnet-10 verifizieren und sechs State-Contracts erst danach auf Mainnet ausrollen | Core Dev + Codex | Canary-Evidence + Metrics Oracle + Release Hardening
- [ ] [P0] kaspa-zk-params Crate integrieren, echte Groth16 in zk_proof.rs | Claude Code | ssc live
- [ ] [P0] PROM Emission Contract schreiben + deployen | Claude Code | ssc live
- [ ] [P0] KAS/PROM Liquiditätspool auf Kasplex DEX eröffnen | Core Dev | Mainnet live
- [ ] [P1] 10 Team Guardian + Validator Nodes starten | Core Dev | Mainnet live

---

## ═══ SPRINT 10: P2P + KRC-20 REAL (Mai-Juni 2026) ═══

- [ ] [P0] libp2p Modul komplett implementieren (peer discovery, NAT, STUN/TURN) | Claude Code | -
- [ ] [P0] Echte KRC-20 UTXO-Abfrage für PROM-RULES Tick | Claude Code | Contracts live
- [ ] [P1] Regel-Download von IPFS via CIDv1 | Claude Code | KRC-20 Reader
- [ ] [P1] Light Client ↔ Guardian P2P Kommunikation | Claude Code | libp2p

---

## ═══ SPRINT 10B: GUARDIAN DECENTRALIZATION (parallel to Sprint 10) ═══

- [x] [P1] Design and implement hybrid routing: 8B default, 70B escalation when confidence < 0.70 | Codex | GH-33/PR #34 merged as `ce1d213`; dependency-injected local router, threat/rule hash binding, finite confidence and strict submission checks, fail-closed escalation, 47 passed/3 live-model skipped; exact-main CI/Security/Pages green; live wiring/calibration remains operational work
- [~] [P1] Implement ensemble voting protocol: 5+ 8B Guardians vote on same YARA rule via majority | Codex | GH-36 local fail-closed protocol merged/exact-main verified at `f8ebaac`; GH-39 BIP340 key/session binding, canonical envelopes/freshness, and owner-only SQLite restart/concurrency/clock-rollback-safe replay/equivocation protection merged/exact-main verified at `d0f78a9`. Actual P2P carrier/discovery/NAT traversal, trusted membership/key assignment, Sybil resistance, on-chain attestation, and production evidence remain
- [ ] [P2] Guardian Pooling Contract: on-chain PROM split for shared 70B nodes | Claude Code | Contracts live
- [ ] [P2] Specialization sharding: Guardian registers attack class (ransomware/network/privilege) during PoW registration | Claude Code | Sprint 11
- [ ] [P2] Sybil resistance final design: KAS/PROM stake per Guardian identity OR hardware ZK-fingerprint | Architect decision needed
- [ ] [P3] Evaluate PLONK vs Groth16 for Light Client ZK-proofs | Claude Code | Post hardfork
- [ ] [P3] YARA-specialized 8B fine-tuning on CVE/YARA datasets only | Claude Code | Sprint 12

---

## ═══ SPRINT 11: PHI-3 + LLAMA PRODUCTION (Juni 2026) ═══

- [ ] [P0] Phi-3-mini 3.8B herunterladen + 4-bit ONNX quantisieren | Claude Code | -
- [ ] [P0] Echte Inferenz statt Entropy-Heuristik in phi3.rs | Claude Code | Phi-3 model
- [ ] [P1] LLaMA 3 8B LoRA Fine-Tuning auf Security-Datensätzen | Claude Code | Datensätze
- [ ] [P1] LLaMA 3 70B Fine-Tuning | Claude Code | 8B done
- [ ] [P2] Fed-DART echte Implementierung (Gradient-Aggregation) | Claude Code | -
- [~] [P2] fp_rate Oracle Contract + Integration | Codex | Current-Silverc contract gate and repository-owned two-input keyless transition operator are merged and exact-main verified at `072f04a` with dual external BIP340 verification, value preservation, separate P2PK fee sponsor, guarded broadcast, and successor observation; real public inputs/signatures/confirmation/evidence remain

---

## ═══ SPRINT 12: DESKTOP CLIENT (Juli-Aug 2026) ═══

- [ ] [P0] Tauri v2 App: System-Tray, Scan-Feed, PROM Balance | Claude Code | Client modules
- [ ] [P0] Windows MSI Installer + Code-Signing | Claude Code | Tauri App
- [ ] [P0] macOS DMG + Gatekeeper Signing | Core Dev | Apple Dev Account nötig
- [ ] [P0] Linux .deb / .AppImage / Flatpak | Claude Code | Tauri App
- [ ] [P0] GitHub Releases CI/CD mit Checksums + GPG | Claude Code | -
- [ ] [P1] One-Click Guardian Installer Script | Claude Code | -
- [ ] [P1] Validator Web Dashboard | Claude Code | -

---

## ═══ SPRINT 13: MOBILE (Aug-Sep 2026) ═══

- [ ] [P0] Flutter Grundgerüst (iOS + Android) | Claude Code | -
- [ ] [P0] iOS: Phi-3 via Core ML, Background Refresh, Keychain | Claude Code | Flutter
- [ ] [P0] Android: Phi-3 via ONNX Mobile, WorkManager, Keystore | Claude Code | Flutter
- [ ] [P1] App Store Submission (iOS) | Core Dev | Apple Dev Account
- [ ] [P1] Google Play + F-Droid (Android) | Core Dev | Play Dev Account

---

## ═══ SPRINT 14: VPROGS (Q4 2026) ═══

- [ ] [P1] vProgs Deployment nach DAGKnight | Claude Code | Kaspa vProgs live
- [ ] [P1] KI-Ergebnisse per ZK-Beweis auf L1 | Claude Code | vProgs
- [ ] [P2] Föderiertes Lernen on-chain auditierbar | Claude Code | vProgs

---

## ═══ ABGESCHLOSSEN ═══

- [x] Whitepaper v1 erstellt | Claude | 2026-03-15
- [x] Whitepaper v2 erstellt (Dev-Incentive-System) | Claude | 2026-03-18
- [x] Whitepaper v3 erstellt (DSGVO, vProgs, LLaMA 8B) | Claude | 2026-03-20
- [x] Whitepaper v4 erstellt (KAS/PROM, Reporter-Pool, Audit-Plan) | Claude | 2026-03-21
- [x] Dev-Review v3: 9/10 | Externer Dev | 2026-03-21
- [x] Dev-Review v4: 10/10 – produktionsreif | Externer Dev | 2026-03-21
- [x] Workflow-Architektur definiert | Claude | 2026-03-21
- [x] Memory-Layer initialisiert | Claude | 2026-03-21
- [x] Landing page index.html erstellt und deployed | Claude | 2026-03-22
- [x] docs/roadmap.md erstellt (vollständige Deployment-Roadmap) | Claude Code | 2026-03-22
- [x] docs/faq.md aktualisiert (12 FAQ-Einträge) | Claude Code | 2026-03-22
- [x] faq.html + roadmap.html deployed to GitHub Pages (Landing-Page-Stil) | Claude Code | 2026-03-22
- [x] whitepaper.html — full HTML version, .md links replaced across all pages | Claude Code | 2026-03-22
- [x] SEO/GEO/AI infrastructure: llms.txt, robots.txt, sitemap.xml, Schema.org | Claude Code | 2026-03-22
- [x] Google Search Console verification + Service Worker + PWA manifest | Claude Code | 2026-03-22
- [x] guardian-economics.html — costs, break-even, solutions | Claude Code | 2026-03-22
- [x] Mobile hamburger navigation on all 5 HTML pages | Claude Code | 2026-03-22
- [x] CI/CD fixed — Rust, Python, contracts, HTML, infra checks | Claude Code | 2026-03-22
- [x] AUDIT.md + ERRORS.md + STATUS.md translated to English | Claude Code | 2026-03-22
- [x] SECURITY.md + docs/repository-security.md + fake email removed | Claude Code | 2026-03-22
- [x] Nav synced across all 5 pages (Architecture + Tokens restored) | Claude Code | 2026-03-22
- [x] PROM coin logo integrated — index, manifest, llms.txt, og:image | Claude Code | 2026-03-22
- [x] KAS official logo added to token card | Claude Code | 2026-03-22
