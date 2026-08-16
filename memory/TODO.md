# PROMETHEUS – TASK QUEUE
# Format: - [ ] [PRIO] Beschreibung | Verantwortlich | Dependencies
# PRIO: P0=Kritisch, P1=Hoch, P2=Mittel, P3=Niedrig
# Status: [ ]=offen, [~]=in Arbeit, [x]=erledigt, [!]=blockiert
# Last Updated: 2026-08-16

---

- [x] [P1] GH-170 substring-only Guardian YARA check durch bounded compile-only YARA-X ersetzen | Codex Sol | PR #171 merged as exact main `8d8e29c`; CI `31650123073`, Security `31650123055`, Pages `31650122593`, review and live readback pass
- [x] [P1] GH-173 deterministic non-actionable semantic draft in governed v2 worker | Codex Sol + Kimi K3 | PR #174 merged as exact main `1107b11`; CI `31654308969`, Security `31654308964`, Pages `31654308875`, review and v1/restart/binding evidence pass
- [x] [P1] GH-197 manifest-bound Testnet-10 RuleStorage UTXO observation | Codex Sol + Kimi K3 | PR #198 merged as exact main `28da2d4`; CI `31904377606`, Security `31904377632`, Pages `31904376972`, independent review and live public-page readback pass; production authority remains false
- [x] [P1] GH-203 live Testnet-10 RuleStorage RPC observation adapter | Codex Sol + Kimi K3 | PR #204 protected delivery; bounded lock/RPC waits, exact node network and returned-address checks, direct pinned-field conversion, unchanged GH-197 verification, and deterministic adversarial tests; independent RPC truth/finality and production authority remain false
- [x] [P1] GH-205 complete-snapshot RuleStorage content sync | Codex Sol + Kimi K3 | PR #206 merged as exact main `11496af`; CI `31913541861`, Security `31913541880`, Pages `31913541497`, independent review and live public-page readback pass; production authority remains false
- [x] [P1] GH-207 durable RuleStorage anti-downgrade checkpoint | Codex Sol + Kimi K3 | PR #208 merged as exact main `a8d3868`; CI `31937017363`, Security `31937017451`, Pages `31937016816`, review and responsive live Roadmap/README readback pass; production authority remains false
- [x] [P1] GH-209 bounded opt-in RuleStorage sync coordinator | Codex Sol + Kimi K3 | PR #210 merged as exact main `d029f9f`; CI `31943658380`, Security `31943658391`, Pages `31943657944`, review and live public-page readback pass; production authority remains false
- [x] [P1] GH-211 authenticated RuleStorage snapshot envelope provider | Codex Sol + Kimi K3 | PR #212 merged as exact main `8fed243`; CI `31947971446`, Security `31947971540`, Pages `31947970820`, review and live README/Roadmap/Whitepaper readback pass; strict canonical Development/Testnet-10 BIP340 envelope only, no signer or authority claim; production authority remains false
- [x] [P1] GH-213 opt-in Development/Testnet-10 RuleStorage sync CLI | Codex Sol + Kimi K3 | PR #214 merged as exact main `bbe7efb`; CI `31950806131`, Security `31950806118`, Pages `31950805653`, local full gates and independent review pass; strict owner-local config/envelope files, offline non-mutating preflight, loopback-IP-literal RPC/IPFS factories, explicit run, redacted status and signal cancellation; no key governance, wallet, chain write, deployment, Mainnet or production authority

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
- [x] [P0] GH-9 H-001 handoff von aktuellem exact main neu bauen | Codex | 2026-07-31 exact main `143a8a0` reproduced the accepted `205e1ca` seven-artifact archive/request/signing request after the dependency-security fix, live-revalidated the public UTXO, passed owner-only modes, full-directory Gitleaks, full Rust/Guardian gates, and independent review; external signature/broadcast/evidence remain
- [x] [P0] GH-30 Required-Check-Laufzeiten begrenzen und Audit-Toolchains pinnen | Codex | PR #31 merged as `71e5783`; alle neun geschützten Kontextnamen unverändert; exact-main CI `29457601210`, Security `29457601183`, Pages `29457600490` green
- [!] [P0] GH-9 `ValidatorStakingH001` Canary auf testnet-10 ausführen | Codex + externer Signer | Funding/identity and exact-main `143a8a0` refresh of the accepted `205e1ca` schema-v2 request/digest are live-revalidated and byte-identical; explicit external BIP340 response, operator verification, separately approved one-shot broadcast, confirmation, receipt, and independent evidence remain
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

- [x] [P1] GH-144/M-005 Guardian-vLLM-Compose reproduzierbar und fail-closed härten (8B + opt-in 70B) | Codex Sol + Kimi K3 | PR #145 squash-merged und exact-main verifiziert als `95d05cc`; CI `30858991436`, Security `30858991557`, Pages `30858990507`. Kein Pull, Download, Live-Modell oder Produktionsnachweis enthalten
- [ ] [P1] vLLM Server für LLaMA 3 8B einrichten (llm_server.py) | Claude Code | Docker
- [ ] [P1] YARA-Regel-Generator implementieren (yara_generator.py) | Claude Code | llm_server.py
- [x] [P2] GH-141 lokale Modellkandidaten-Evidence erfassen und offline verifizieren | Codex Sol + Kimi K3 | PR #142 squash-merged und exact-main verifiziert als `bf3f74f`; CI `30727224584`, Security `30727224572`, Pages `30727224235`. Kein Live-Modelllauf oder Produktionsnachweis enthalten
- [ ] [P1] Bedrohungsanalyse-Pipeline (analyzer.py) | Claude Code | yara_generator.py
- [ ] [P2] Reputationsberechnung (reputation/scoring.py) | Claude Code | -
- [ ] [P2] Guardian ↔ Validator Kommunikation (Proposal senden) | Claude Code | Contracts deployed
- [ ] [P2] Tests: Guardian erkennt Malware-Sample, generiert YARA-Regel | Claude Code | Alle Guardian-Module

---

## ═══ SPRINT 5: VOTING MECHANISMUS (Woche 7) ═══

- [~] [P1] Commit-Reveal vollständig in Silverscript implementieren | Claude Code | H-001 runtime fixture + ValidatorStakingState compile/ABI + commitVote/revealVote/slash/requestWithdraw/completeWithdraw runtime gates done; signed-int deployment bounds enforced; GuardianReputationState/RuleStorageState/CommunityDonationsState/DevIncentivePoolState/GovernanceAutoTuningState compile/ABI/runtime gates done locally; current-Silverc artifact smoke/release archive/deploy preflight/deploy request generation/verification and the merged repository-owned keyless genesis assembly/verification/broadcast path pass locally and in main CI; public receipts/evidence/status staging, metrics-oracle, and release-hardening gates are implemented; the isolated H-001 Testnet-10 canary is confirmed and independently evidenced, while the remaining state deployments and production rollout gates remain
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
- [x] [P0] H-001 schema-v2 Request/Digest vom exact-main Commit neu bauen | Codex | Deterministic rebuild and live funding preflight pass; signing-request `6b8e6506...a5323`; superseded by the completed canary below
- [x] [P0] `ValidatorStakingH001` Canary real ausführen; nie als Full-/Metrics-Readiness promoten | Codex Sol + externer Signer | Testnet-10 BIP340 response, full transaction verification, exactly one journaled broadcast, confirmed covenant output, `operator_record`, and independent public evidence pass; tx `c85fd1e7...c22f`; no other deployment authorized
- [!] [P0] Full-Profil: sieben Release-Fixtures auf testnet-10 verifizieren und sechs State-Contracts erst danach auf Mainnet ausrollen | Core Dev + Codex | Canary-Evidence + Metrics Oracle + Release Hardening
- [~] [P0] Echte KIP-16/Groth16 ThreatHint-Verifikation produktiv schalten | Codex + independent reviewer | GH-63 engine/adapter/service merged and exact-main verified; approved production relation, VK, independent vectors, and artifact ceremony remain
- [ ] [P0] PROM Emission Contract schreiben + deployen | Claude Code | ssc live
- [ ] [P0] KAS/PROM Liquiditätspool auf Kasplex DEX eröffnen | Core Dev | Mainnet live
- [ ] [P1] 10 Team Guardian + Validator Nodes starten | Core Dev | Mainnet live

---

## ═══ SPRINT 10: P2P + KRC-20 REAL (Mai-Juni 2026) ═══

- [~] [P0] libp2p Modul komplett implementieren | Codex | GH-42/GH-44/GH-48/GH-52/GH-55/GH-58/GH-63 are merged/exact-main verified, including the real manifest-pinned KIP-16 Groth16 engine and bounded owner-aware service. Real two-host evidence is blocked until private operator access is independently verified. Broad discovery and remaining client/validator paths stay open; mDNS remains excluded by the unresolved compatible RustSec dependency path
- [ ] [P0] Echte KRC-20 UTXO-Abfrage für PROM-RULES Tick | Claude Code | Contracts live
- [~] [P1] Regel-Download von IPFS via CIDv1 | Codex Sol + Kimi K3 | GH-190 through GH-209 provide bounded exact-byte verification, restricted loopback gateway fetch, atomic complete-snapshot activation, restart-persistent anti-downgrade state and an opt-in development coordinator; canonical L1 authority, autonomous replicated IPFS operation and production YARA remain
- [~] [P1] Light Client ↔ Guardian P2P Kommunikation | Codex | GH-55 canonical schema/client builder/direct P2P core, GH-58 durable ingress, GH-63's real active-KIP-16 BN254/Arkworks verification engine plus bounded owner-aware adapter/service, GH-74's bounded digest/network/time-bound analyzer adapter, and GH-77's per-job batch isolation/data-minimal report are merged/exact-main verified. Hash-only v1 input remains an exact non-submittable no-LLM/no-YARA result. Operated acceptance stays fail-closed `busy` until independently approved production relation/VK/vectors are installed; actionable analysis also requires a reviewed privacy-preserving concrete-observable channel or future schema
- [x] [P1] Threat Observable v2 privacy contract | Codex + independent reviewers | GH-82/PR #83 merged/exact-main verified as `fceff1d`; separate artifact hash and observable commitment, strict canonical bounds, deny-by-default disclosure, and corrected public claims
- [x] [P1] Local Threat Observable bundle validators and vectors | Codex + helper agents | GH-86/PR #87 merged/exact-main verified as `2bfe5a3`; matching Rust/Python canonical validation and commitment against 5 valid, 35 invalid-bundle, and 9 invalid-context shared vectors; CI `29981646898`, Security `29981646867`, and Pages `29981646320` pass
- [x] [P1] Local `file_sha256` producer from exact artifact bytes | Codex + helper reviewers | GH-90/PR #91 merged as exact main `e7f34bb`; one digest is computed internally from bytes plus typed scope, with no path/digest/generic builder input and shared Rust-producer/Python-validator vectors; CI `29984477087`, Security `29984476876`, and Pages `29984476107` pass
- [x] [P1] Local review-required `byte_pattern` producer | Codex + helper reviewers | GH-94/PR #97 merged as exact main `34ab5b7`; one bounded pattern derives from exact bytes, checked offset, boolean wildcard mask, and typed scope; at least eight fixed bytes, no pattern/path/generic builder input, mandatory local-only `review_required_v1`, and shared Rust-producer/Python-validator vectors; CI `29989116631`, Security `29989117912`, and Pages `29989118948` pass
- [x] [P1] Guardian sidecar signal listeners before readiness | Codex + Claude Code review | GH-100/PR #101 merged as exact main `83bdfe0`; Unix SIGINT/SIGTERM listeners install before operator output in the explicitly Unix-only crate; pre-fix stress reproduced at iteration 24, patched stress passed 64/64; CI `29994190542`, Security `29994190564`, and Pages `29994189428` pass
- [x] [P1] Local review-required Linux ELF `api_import` producer | Codex + Claude Code + Terra review | GH-103 merged through protected PR #104 as exact main `42d9cd9`; CI `29999873100`, Security `29999873126`, Pages `29999872424`, and live public markers pass; derives one import from exact ELF bytes plus a checked sorted/deduplicated index with 16 MiB/4096-symbol limits and no path/string/generic builder or transport/proof/analyzer/chain wiring
- [x] [P1] Local Observable Approval v1 verifier | Codex + Claude Code + Terra review | GH-107 merged through protected PR #108 as exact main `fc6f1c9fdcfb74c4858b12ec9265ebd6cee10dfe`; CI `30006654048`, Security `30006654027`, Pages `30006653208`, and live public markers pass; matching Rust/Python canonical BIP340 verification uses a shared public-only vector, exact trusted context, separately trusted non-attacker-controlled time, and a one-hour cap; no signer, replay ledger, transport, promotion, disclosure, analyzer, proof, wallet, or chain wiring
- [x] [P1] Local durable Observable Approval consumption | Codex + Terra/Spark review | GH-111 merged through protected PR #112 as exact main `60166bd6d8d3c7d8e88727c2f6d507b206a308ad`; CI `30011976919`, Security `30011976853`, Pages `30011975363`, and raw/live public markers pass; owner-only exact-schema fixed network/approver-key/recipient-scope policy, same-call GH-107 verification, atomic approval-ID plus authority-nonce SQLite consumption, clock high-water, restart/concurrency/lock/path/schema hardening, and data-only receipts; no pairing, promotion, analyzer, outbox, wallet, or chain wiring
- [x] [P1] Local canonical ThreatHint v2 statement | Codex + Terra/Spark review | GH-114 merged through protected PR #115 as exact product main `70bb8ab`; CI `30019079713`, Security `30019079960`, Pages `30019075639`, and raw/live markers pass; independent Rust/Python exact canonical parsers consume one shared 8-valid/20-invalid byte corpus for separate artifact hash and observable commitment plus confidence, structural disclosure class, nonce, time, and separately trusted network without operational wiring
- [x] [P1] Local review-required Windows PE `api_import` producer | Codex Sol + Kimi implementation/review | GH-121 merged through protected PR #122 as exact main `2e3e1e1`; CI `30493381824`, Security `30493381812`, and Pages `30493381150` pass; exact caller-supplied PE32/PE32+ bytes plus checked sorted/deduplicated import index, internally fixed `windows`/`pe` scope, 16 MiB, 4096-import-descriptor, and 4096-thunk-entry bounds, ordinal, malformed-table, and bound-IAT-without-lookup-table fail-closed handling, synthetic shared vectors, independent Python validation, two-library descriptor/deduplication coverage, and positive unbound-IAT fallback coverage; Kimi reviews found no remaining P0/P1/P2; no paths, arbitrary strings, pairing, proof, transport, analyzer, wallet, chain, or promotion wiring

---

## ═══ SPRINT 10B: GUARDIAN DECENTRALIZATION (parallel to Sprint 10) ═══

- [x] [P1] Design and implement hybrid routing: 8B default, 70B escalation when confidence < 0.70 | Codex | GH-33/PR #34 merged as `ce1d213`; dependency-injected local router, threat/rule hash binding, finite confidence and strict submission checks, fail-closed escalation, 47 passed/3 live-model skipped; exact-main CI/Security/Pages green; live wiring/calibration remains operational work
- [~] [P1] Implement ensemble voting protocol: 5+ 8B Guardians vote on same YARA rule via majority | Codex | GH-36/39 plus merged/exact-main GH-42/GH-44/GH-48/GH-52 are implemented. Public/multi-host operation, broad discovery, trusted membership/key assignment, Sybil resistance, on-chain attestation, and production evidence remain
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
- [x] [P1] Local canonical ThreatHint-v2 proof-envelope, RelationManifest-v2, and atomic data-only binding candidate | Codex Sol + Kimi K3 | 2026-07-26 | 5 valid/28 invalid shared binding vectors; full local gates and final no-finding review pass; not committed, merged, published, or deployed
- [x] [P1] Local non-consuming ThreatHint-v2 privacy/proof preflight candidate | Codex Sol + Kimi K3 | 2026-07-26 | Owner-only policy pins network/approver/scope/manifest; statement derived only from bound envelope; 31 focused cases and full local gates pass; no proof verification, approval consumption, SQLite mutation, commit, publish, or deploy
- [x] [P1] Local trusted ThreatHint-v2 Groth16 verifier candidate | Codex Sol + Kimi K3 | 2026-07-26 | Owner-only manifest/source/VK binding, no runtime proving key, real Arkworks verification, 16 adversarial CLI cases and full gates pass; deterministic fixtures only, not committed/published/deployed
- [x] [P1] Local non-consuming ThreatHint-v2 verified-preflight composition | Codex Sol + Kimi K3 | 2026-07-27 | Owner-pinned executable SHA-256, sole policy network/manifest anchors, Python preflight before bounded shell-free `verify-v2`, 59 focused and 310 complete Guardian cases pass; no SQLite, consumption, commit, publish, or deploy
- [x] [P1] Local raw-input-only ThreatHint-v2 atomic acceptance candidate | Codex Sol + Kimi K3 | 2026-07-27 | Exact policy identity before ledger creation; verified proof/privacy preflight first; approval-ID/commitment binding before final durable consume; 158 focused and 349 complete Guardian cases pass; no production artifact approval, external effect, commit, publish, or deploy
- [x] [P1] Local owner-policy ThreatHint-v2 promotion/pairing candidate | Codex Sol + Kimi K3 | 2026-07-27 | Exact owner-only platform/format/kind/count policy before raw atomic acceptance; check-to-open race hardening; 57 focused, 207 combined, and 406 complete Guardian cases pass; no semantic privacy, transport, analysis, external effect, commit, publish, or deploy
- [x] [P1] Local owner-only outbox retention-governance candidate | Codex Sol + Kimi K3 | 2026-07-27 | Exact network/approver/scope-bound retention declaration; 114 focused and 520 complete Guardian cases pass; no database, outbox, runtime, external effect, commit, publish, or deploy
- [ ] [P0] Approve real v2 relation source, proving/verifying keys, ceremony evidence, and independent cryptographic evidence for the trusted verifier | Core Dev + independent cryptography review | Blocks operated v2 proof rollout; local test-artifact verification and atomic acceptance mechanics are not production artifact approval
- [x] [P0] Define and locally enforce authority/key governance, fixed recipient semantics, and per-kind privacy decisions | Codex Sol + Kimi K3 | Ticket 012 local candidate pins exact promotion/governance/retention digests plus authority identity/window atomically with valid approval consumption; no production identity attestation, commit, merge, or deploy
- [x] [P0] Implement an atomic recoverable local outbox/claim before v2 transport or actionable analysis | Codex Sol + Kimi K3 | Ticket 013 governed-only schema v3 stores the full canonical bundle atomically with authority/high-water/consumption; bounded claim/lease/recovery/ack tests and complete local gates pass; no worker, external effect, commit, merge, publish, or deploy
- [x] [P0] Implement and independently review the bounded v2 outbox worker plus durable non-actionable completion substrate | Codex Sol + Kimi K3 | Ticket 014 governed schema v4 binds statement/nonce/bundle/approval/lease/retention, atomically stores one canonical non-actionable result before deleting work, and keeps existing Analyzer/LLM/YARA/actionable output disabled; 72 focused and Guardian 740 pass/3 skip plus complete Rust/lint/build/audit/docs gates
- [ ] [P0] Design and separately approve real privacy-reviewed semantic analysis and actionable-rule integration | Core Dev + independent security/privacy review | Must not reuse the legacy heuristic Analyzer as v2 submission authority; requires deterministic result semantics, YARA validation, privacy review, crash-safe downstream effects, and a new explicit high-risk ticket
- [x] [P2] Resolve M-002 debug commitment benchmark flakiness without weakening the release target | Codex Sol | GH-131 merged as exact main `6687f1e`; CI `30673669760`, Security `30673669848`, and Pages `30673669405` pass with ten strict contexts
- [x] [P2] Remediate `RUSTSEC-2026-0221` in transitive `event-listener` | Codex Sol | GH-132 merged and exact-main verified at `42acbca`; CI `30676094287`, Security `30676094290`, and Pages `30676093914` pass
- [x] [P2] Replace heuristic YARA confidence with strict model-provided integer basis points | Codex Sol | GH-135/PR #136 merged and exact-main verified at `3ff3fa1`; CI `30694395348`, Security `30694395356`, and Pages `30694394857` pass. Live semantic/adversarial evaluation and calibration remain separate rollout work
- [x] [P2] Add deterministic Guardian confidence evaluation/calibration gate | Codex Sol | GH-138/PR #139 merged and exact-main verified at `52209cc`; CI `30697333650`, Security `30697333643`, and Pages `30697333307` pass. The canonical 24-case synthetic evidence is internally consistency-checked but not externally anchored. Live-model semantic quality, real adversarial evidence, production calibration, and authorization remain separate gates
- [x] [P3] Disable reconstruction/serialization of the older data-only `ThreatHintV2PreflightReceipt` | Codex Sol | Closed in ticket 009 with direct, `dataclasses.replace`, and pickle regressions
- [x] [P1] GH-147 canonical Guardian membership source and public-key assignment | Codex Sol + Kimi K3 | PR #148 merged as exact main `aeecffb`; CI `30863940497`, Security `30863940502`, and Pages `30863940053` pass after 198 focused tests, Guardian 1043/4, Black 30 and Pylint 10.00/9.84. External source authority, key ownership/rotation, Sybil resistance and L1 attestation remain separate work
- [x] [P1] GH-152 permanent governed ThreatHint-v2 identity pairing | Codex Sol + Kimi K3 | PR #153 merged as exact main `3d203aa`; CI `31306353671`, Security `31306353670`, and Pages `31306353328` pass after 63 focused and 1050/4 full Guardian tests; Kimi final review PASS with no P0-P2
- [x] [P2] GH-155 Guardian sidecar process-test CI stability | Codex Sol + Kimi K3 | PR #156 merged as exact main `db33f56`; CI `31308756777`, Security `31308756786`, and Pages `31308756387` pass after deterministic kill/reap coverage, 20-pass stress, full local gates, and Kimi review PASS with no P0-P2; test-only, no production behavior
- [x] [P2] GH-158 synchronize August public status and GH-155 reliability evidence | Codex Sol + Kimi K3 | PR #159 merged as exact main `ed75b58`; CI `31311389618`, Security `31311389613`, and Pages `31311389052` pass; live Pages verified, H-001 remains 96% and core rollout remains 84-88%
- [x] [P1] GH-161 derive Guardian candidate model digest from exact owner-local artifacts | Codex Sol + Kimi K3 | PR #162 merged as exact main `d468426`; CI `31340112225`, Security `31340112204`, and Pages `31340111625` pass; canonical manifest and capture-time re-verification only, no upstream authenticity or production model authority
- [x] [P1] GH-167 bounded ThreatHint-v2 repository transport substrate | Codex Sol + Kimi K3 | PR #168 merged normally as exact main `7c62608`; CI `31645624623`, Security `31645624601`, and Pages `31645623547` pass. Exact Rust/Python framing, independent libp2p v2 channel, owner-only ingress, trusted network/session/time revalidation, bounded acknowledgements/budgets, adversarial corpus, and separate-process same-host evidence are merged and live. Production proof approval, semantic/actionable analysis, disclosure, operated public multi-host evidence, model/YARA, wallet, chain, reward, and deployment remain separate gates
- [x] [P1] GH-177 isolated synthetic YARA semantic-quality gate | Codex Sol + Kimi K3 | PR #178 merged as exact main `396d347`; CI `31658560850`, Security `31658560811`, and Pages `31658560331` pass after a 20-case deterministic in-memory corpus, exact corpus/policy/evaluator/engine binding, strict authority-none report, 26 focused and 1295/4 full Guardian tests, complete gates and no-finding final review
- [x] [P1] GH-180 deterministic offline ThreatHint-v2 pipeline integration gate | Codex Sol + Kimi K3 | PR #181 merged as exact main `a28ad00`; CI `31662874366`, Security `31662874399`, and Pages `31662873670` pass after 8 new and 171 adjacent tests, 1303 Guardian tests passed/4 intentional live-model tests skipped, Kimi no-P0/P1/P2 review, and two resolved CodeRabbit threads; test composition only, no product runtime or production authority
- [x] [P1] GH-193 strict RuleStorage constructor-state decoder | Codex Sol + Kimi K3 | PR #194 merged as exact main `d0cd087`; CI `31900314121`, Security `31900314143`, and Pages `31900313745` pass. Canonical RPC provenance, covenant-instance/finality proof and live IPFS retrieval remain separate tasks
