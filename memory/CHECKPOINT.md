# PROMETHEUS — SESSION CHECKPOINT
# Last updated: 2026-03-22
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
| Letzter Commit | aec339d — fix: logo higher + dimming + node text mint |
| Whitepaper | WHITEPAPER.md (root) + Prometheus_Whitepaper_v4.docx (Referenz) |
| Status | Feature-complete. Warten auf Covenant-Hardfork 5. Mai 2026. |

---

## ROLLEN

| Rolle | Wer | Aufgabe |
|-------|-----|---------|
| Core Dev | NeaBouli | Triggert Tasks, entscheidet über Sprints |
| Architect / Auditor | Claude (claude.ai) | Architektur, Audit, Antworten auf QUESTION FOR CLAUDE |
| Implementierung | Claude Code | Schreibt Code, Tests, Commits, Pushes |

**Kommunikationsweg bei Blockaden:**
Claude Code → schreibt in memory/AUDIT.md: "QUESTION FOR CLAUDE: <frage>"
Core Dev → sendet Frage an Claude (Architect) im Chat
Claude → antwortet, Core Dev trägt Antwort in memory/MEMO.md ein

---

## SPRINT-STATUS (alle abgeschlossen)

| Sprint | Status | Commit-Bereich | Deliverables |
|--------|--------|----------------|--------------|
| 0 — Setup | ACCEPTED | fdc5f24 | Testnet-10 Node, Repo-Struktur, CI/CD |
| 1 — Contracts | ACCEPTED | 5d08a58, de23917 | 6 Silverscript Contracts, 54 Tests |
| 2 — Client | ACCEPTED | 2e0e8ee, 27010a5 | Rust RPC, YARA, ZK-stub, KRC-20 |
| 3 — AI | ACCEPTED | 9c13981 | Phi-3 ONNX, AnomalyDetector, Fed-DART |
| 4 — Guardian | ACCEPTED | 1339084 | Docker vLLM, YARA Generator, Analyzer |
| 5 — Voting | ACCEPTED | fb076cb | Commit-Reveal, Bond, SlashingEngine |
| 6 — E2E | ACCEPTED | de0d4ef | Lifecycle <60s, Sybil-Proof, FP-Flood |
| 7 — Dashboard | ACCEPTED | dc20deb | Audit-Dashboard, README.md, WHITEPAPER.md |
| 8 — Docs | DONE | 892a9b5 | CONTRIBUTING.md, 5 Wiki-Guides |
| Landing Page | DONE | aec339d | index.html — dark theme, mint green, ambient logo |
| Wiki Pages | DONE | af1a06a | faq.html + roadmap.html — coherent with landing page |
| Whitepaper HTML | DONE | 8c950f6 | whitepaper.html — full HTML version, all .md links replaced |
| SEO/GEO/AI | DONE | b696d5b | llms.txt, robots.txt, sitemap.xml, Schema.org all pages |
| Google + PWA | DONE | 20e8531 | Search Console verified, SW, manifest.json |

---

## OFFENE TODOS (Claude Code)

- [ ] GitHub Pages aktivieren (Core Dev: Settings → Pages → main / root)
- [x] Wiki-Seiten im Landing-Page-Stil bauen (kohärent) — faq.html + roadmap.html deployed
- [ ] Gitcoin Grants Antrag finalisieren (April 2026) — Core Dev
- [ ] Repository public schalten — Core Dev (nach Sprint 6 fertig = jetzt)
- [ ] LLaMA 3 Fine-Tuning auf Security-Datensätzen (P3, nach Mainnet)
- [ ] Discord/Telegram aufbauen — Core Dev
- [ ] PATTERN-010 in production: Arc<Phi3Model> statt Arc<Mutex<Phi3Model>>
- [ ] fp_rate Oracle-Mechanismus entscheiden (Q-003 in AUDIT.md offen)
- [ ] Guardian hybrid routing (8B/70B) — Sprint 10B, BEFORE mainnet
- [ ] Ensemble voting protocol (5x 8B majority) — Sprint 10B
- [ ] Sybil resistance final design — Architect decision needed
- [ ] PLONK evaluation for Light Client ZK-proofs — Sprint 9+

---

## KRITISCHE ARCHITEKTURREGELN (nie vergessen)

1. VALIDATORS staken KAS — tx.value = KAS, Konstante = MIN_STAKE_KAS
2. PROM wird VERDIENT (Guardians) — niemals gestaked von Validators
3. Kein Emergency-Stop — by design, kein Killswitch implementieren
4. slash() hat ACL: nur GOVERNANCE_CONTRACT oder RULE_STORAGE_CONTRACT
5. float64 → uint64 mit 10000x Skalierung in allen Contracts
6. IPFS CID = bytes(36) binär CIDv1 (nicht bytes(46), nicht CIDv0)
7. commit-Reveal: sha256(vote_byte || salt_le || block_height_le)
8. Immer: cargo fmt + cargo clippy --D warnings vor jedem Commit
9. Testnet = kaspa-testnet-10 (Testnet-12 existiert nicht)
10. ssc Compiler erscheint mit Covenant-Hardfork am 5. Mai 2026

---

## BEKANNTE FEHLER-MUSTER (ERRORS.md Zusammenfassung)

| ID | Problem | Lösung |
|----|---------|--------|
| P-001 | KAS/PROM Verwechslung | grep -n "MIN_STAKE" vor Commit |
| P-002 | ssc ohne --testnet Flag | ssc compile --testnet --network testnet-10 |
| P-003 | std::sync::Mutex in async | tokio::sync::Mutex verwenden |
| P-004 | Groth16 Parameter-Mismatch | kaspa-zk-params Crate verwenden |
| P-005 | CIDv0 statt CIDv1 | ipfs add --cid-version 1, CID beginnt mit "bafy" |
| P-006 | float64 Vergleiche | abs(a-b) < 0.001 für Epsilon-Vergleiche |
| P-007 | libp2p NAT-Problem | STUN/TURN einrichten |
| P-008 | Datei nicht auf Disk | grep verifizieren VOR git commit |
| P-009 | yara C-Dependency | Custom Matcher in scanner.rs, yara-x für Production |
| P-010 | Unnötige Mutex auf Phi3Model | Arc<Phi3Model> statt Arc<Mutex<Phi3Model>> |
| P-011 | Heuristische Confidence | LLM-Confidence-Extraktion für Production |

---

## TECHNOLOGIE-STACK

| Komponente | Tech | Pfad |
|-----------|------|------|
| Blockchain | Kaspa, rusty-kaspa | /tmp/rusty-kaspa |
| Smart Contracts | Silverscript (.ss) | modules/contracts/ |
| Rust Client | Rust + Tauri | modules/client/ |
| Guardian Node | Python + Docker | modules/guardian-node/ |
| Validator Node | Rust | modules/validator-node/ |
| Web / Dashboard | HTML + CSS | modules/web/audit/ |
| Landing Page | HTML + CSS | index.html (root) |
| Logo | PNG | logo/Prometheus.png |
| Memory Layer | Markdown | memory/ (8 Dateien) |

---

## DESIGN-SYSTEM (Landing Page / Wiki — kohärent halten)

| Variable | Wert | Verwendung |
|----------|------|-----------|
| --void | #050505 | Haupthintergrund |
| --mint | #00E5A0 | Primärer Akzent, Labels, CTAs |
| --mint-dim | #00B880 | Sekundärer Mint |
| --silver | #C8C8C8 | Haupttext, Überschriften |
| --silver-dim | #787878 | Sekundärtext |
| --gold | #C8A060 | Timestamps, kleine Labels |
| Font Display | Space Mono (700) | Wordmark, Labels, Badges |
| Font Body | Space Grotesk (300/400) | Fließtext |
| Grid | 80px, opacity 0.07 | Hero-Hintergrund |
| Scanlines | 2px repeat | Body overlay |

---

## NÄCHSTE SCHRITTE (Priorität)

1. GitHub Pages aktivieren → https://neabouli.github.io/prometheus-/
2. Repository public schalten
3. Wiki-Seiten im Landing-Page-Stil (kohärent)
4. Gitcoin Grants Antrag einreichen (Deadline: April 2026)
5. 5. Mai 2026: ssc Compiler → Contracts auf Testnet-10 deployen

---

---

## FAQ-BANK (für Wiki und Landing Page)

Diese Fragen wurden im Architect-Chat gesammelt und beantwortet.
Sie fließen in docs/faq.md und eine zukünftige FAQ-Seite ein.

### Q: Wie funktioniert das Zwei-Token-Modell?
KAS = wirtschaftliche Kaution der Validators (Slashing bei Betrug).
PROM = Belohnung für geleistete Sicherheitsarbeit (nie kaufbar, nur verdient).
Getrennte Rollen verhindern dass Kapital = Einfluss.

### Q: Wie kommt PROM in den Markt?
Tag 1: Erste PROM entstehen wenn erste Regel akzeptiert wird (0 Vorallokation).
Gleichzeitig: KAS/PROM Liquiditätspool auf Kasplex DEX (aus Community-Pool).
Preis entsteht organisch — kein ICO, kein Listing-Preis.
Deflation (-10%/Jahr) bei wachsender Nutzernachfrage = natürlicher Preisdruck.

### Q: Werden Bedrohungsregeln automatisch bestätigt?
Nein — 4 Stufen:
1. KI-Vorfilter: min. 85% Konfidenz (automatisch)
2. Sammlung: min. 5 unabhängige Meldungen (automatisch)
3. Validator-Abstimmung: 67% Mehrheit, Commit-Reveal, Bond-Verlust bei Betrug
4. 24h Challenge-Period: Einsprüche möglich, Auto-Tuning reagiert auf FP-Rate

### Q: Was passiert bei einer False Positive?
Betroffene Nutzer melden → FP-Rate steigt → Auto-Tuning erhöht Schwellenwert
automatisch → Guardian der schlechte Regel eingereicht hat verliert 50% Reputation.
Kein Mensch muss eingreifen.

### Q: Gibt es Mining bei PROM?
Nein im klassischen Sinne. PROM wird "geminted" wenn eine Regel akzeptiert wird.
Das ist leistungsbasierte Emission — näher an "Arbeitsnachweis" als an PoW-Mining.
Guardians = die "Miner" des Prometheus-Netzwerks (mit KI statt GPU-Hashrate).

---

## PENDING FAQ (noch nicht beantwortet — für zukünftige Sessions)

- Wie funktioniert föderiertes Lernen konkret für Endnutzer?
- Was passiert wenn ein Guardian-Node offline geht?
- Kann PROM später auf anderen Börsen gehandelt werden?
- Wie schützt ZK-Proof die Privatsphäre des Melders?
- Was ist der Unterschied zwischen Prometheus und ClamAV/Wazuh?

---

---

## REVISED TIMELINE (confirmed 2026-03-22)

Target: Full release August / September 2026.
Daily development.

| Month | Milestone |
|-------|-----------|
| May 2026 | Contracts live, first PROM, DEX pool |
| June 2026 | ZK-proof real, P2P, Phi-3 production, LLaMA fine-tuned |
| July 2026 | Desktop client beta |
| August 2026 | Full desktop release + Guardian installer |
| September 2026 | iOS + Android mobile clients |
| Q4 2026 | vProgs integration |

---

*Prometheus v4.0 · Checkpoint 2026-03-22 · Last updated: 46cd28b PROM coin logo · The fire belongs to humanity.*
