# PROMETHEUS – TASK QUEUE
# Format: - [ ] [PRIO] Beschreibung | Verantwortlich | Dependencies
# PRIO: P0=Kritisch, P1=Hoch, P2=Mittel, P3=Niedrig
# Status: [ ]=offen, [~]=in Arbeit, [x]=erledigt, [!]=blockiert
# Last Updated: 2026-03-21

---

## ═══ SPRINT 0: SETUP & TESTNET (Woche 1) ═══

- [x] [P0] Repo-Struktur auf GitHub anlegen (memory/, modules/, scripts/, .gitignore) | Claude Code | 2026-03-21
- [ ] [P0] Alle memory/-Dateien initial befüllen und pushen | Claude Code | Repo-Struktur
- [x] [P0] Kaspa Testnet-10-Node installieren und starten (rusty-kaspa v1.1.0) | Claude Code | 2026-03-21
- [x] [P0] Verbindung zum Testnet verifizieren (8 Peers, IBD active) | Claude Code | 2026-03-21
- [ ] [P0] Silverscript Compiler (ssc) installieren und testen | Claude Code | PENDING: ssc kommt mit Covenant-Hardfork 05.05.2026
- [ ] [P0] Hello-World Silverscript Contract auf Testnet deployen | Claude Code | PENDING: Deployment nach ssc-Release
- [x] [P0] rusty-kaspa als Dependency in Cargo.toml einbinden | Claude Code | 2026-03-21
- [ ] [P0] autodidactic.py vollständig testen (alle Memory-Operationen) | Claude Code | memory/-Dateien
- [x] [P0] .gitignore konfigurieren (.secrets/, /tmp/, target/, __pycache__) | Claude Code | 2026-03-21
- [x] [P0] GitHub Actions CI/CD Grundkonfiguration (build + test) | Claude Code | 2026-03-21 (ci.yml aus Setup)

---

## ═══ SPRINT 1: CORE CONTRACTS (Woche 2-3) ═══

- [x] [P1] ValidatorStaking.ss schreiben (register, commitVote, revealVote, slash) | Claude Code | 2026-03-21 (11 tests)
- [x] [P1] GuardianReputation.ss schreiben (register, submitContribution, votingPower) | Claude Code | 2026-03-21 (9 tests)
- [x] [P1] GovernanceAutoTuning.ss schreiben (auto_tune, alle Parameter) | Claude Code | 2026-03-21 (8 tests, fp_rate stub)
- [x] [P1] DevIncentivePool.ss schreiben (proposeGrant, vote, payGrant, recommended_reward) | Claude Code | 2026-03-21 (9 tests)
- [x] [P1] CommunityDonations.ss schreiben (donateKas, getDonations) | Claude Code | 2026-03-21 (8 tests)
- [x] [P1] RuleStorage.ss schreiben (storeRule als KRC20-Asset) | Claude Code | 2026-03-21 (9 tests)
- [x] [P1] Unit-Tests für ValidatorStaking (min. 10 Tests) | Claude Code | 2026-03-21 (11 tests)
- [x] [P1] Unit-Tests für GuardianReputation (min. 8 Tests) | Claude Code | 2026-03-21 (9 tests)
- [ ] [P1] Alle Contracts auf Testnet deployen und Adressen in STATUS.md eintragen | Claude Code | Wartet auf ssc (05.05.2026)
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

- [ ] [P1] Commit-Reveal vollständig in Silverscript implementieren | Claude Code | ValidatorStaking.ss
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
- [x] [P2] README.md rewrite in English | Claude Code | 2026-03-22
- [x] [P2] WHITEPAPER.md: full English whitepaper v4 in repo, with all improvements | Claude Code | 2026-03-22
- [x] [P2] CONTRIBUTING.md erstellen | Claude Code | 2026-03-22
- [x] [P2] Wiki-Grundstruktur (docs/) | Claude Code | 2026-03-22
- [x] [P2] Landing page + Wiki: use logo from /logo/Prometheus.png | Claude Code | 2026-03-22
- [ ] [P3] Discord/Telegram einrichten | Core Dev | -

---

## ═══ SPRINT 9: CONTRACTS LIVE (Mai 2026) ═══

- [ ] [P0] ssc compile + deploy alle 6 Contracts auf Kaspa Mainnet | Claude Code | Covenant-Hardfork
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

- [ ] [P1] Design hybrid routing algorithm: 8B default, 70B escalation when confidence < 0.70 | Claude Code | Sprint 9 done
- [ ] [P1] Implement ensemble voting protocol: 5+ 8B Guardians vote on same YARA rule via majority | Claude Code | Sprint 10
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
- [ ] [P2] fp_rate Oracle Contract + Integration | Claude Code | Contracts live

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
