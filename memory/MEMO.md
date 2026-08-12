# PROMETHEUS – PERSISTENT MEMORY (MEMO)
# Version: 4.0
# Last Updated: 2026-08-13
# Maintainer: Claude Code (auto-update) + Claude (audit)
#
# WICHTIG: Diese Datei ist das Langzeitgedächtnis des Projekts.
# Claude Code liest sie bei JEDEM Start. Niemals löschen.
# Änderungen nur durch Claude (Architect) oder Core Dev.

---

## PROJEKT-IDENTITÄT

| Eigenschaft        | Wert                                                   |
|--------------------|--------------------------------------------------------|
| Projektname        | Prometheus                                             |
| Token              | PROM (Prometheus Token)                                |
| GitHub             | https://github.com/NeaBouli/prometheus-                |
| Ziel-Launch        | 5. Mai 2026 (Kaspa Covenant-Hardfork)                  |
| Whitepaper         | Prometheus_Whitepaper_v4.docx (im Repo)                |
| Status             | Phase 0 – Vorbereitung                                 |
| Core Dev           | NeaBouli                                               |
| Architect / Auditor| Claude (claude.ai)                                     |
| Implementierung    | Claude Code (autonomous agent)                         |
| Logo               | /logo/Prometheus.png                                   |

---

## ARCHITEKTUR-ENTSCHEIDUNGEN (unveränderlich, nummeriert)

Diese Entscheidungen sind final. Claude Code darf NICHT davon abweichen.
Abweichungen führen zu automatischem REJECT im Audit.

| #  | Entscheidung                          | Begründung                                      | Datum      |
|----|---------------------------------------|-------------------------------------------------|------------|
| 1  | KAS = Staking-Asset der Validators    | KAS ist etabliert, liquide, 0% Pre-Mine         | 2026-03-21 |
| 2  | PROM = earned-only Reward/Governance  | Verifizierte Sicherheitsarbeit verdient PROM; der kanonische Guardian-Reputationswert bleibt separater Kaspa-L1-State | 2026-03-21 / clarified 2026-07-16 |
| 3  | Kein Emergency-Stop                   | Ultimative Dezentralisierung – Feature, kein Bug| 2026-03-21 |
| 4  | Keine Foundation, kein Gründer-Pool   | 0% Pre-Mine, genau wie Kaspa                    | 2026-03-21 |
| 5  | Governance: vollautomatisch           | Code ist das Gesetz – kein menschlicher Eingriff| 2026-03-21 |
| 6  | Jaeger-KI: LLaMA 3 70B (Pflicht)      | State-of-the-Art Open Source                    | 2026-03-21 |
| 7  | Jaeger-KI: LLaMA 3 8B (Fallback)      | Niedrigere Hardware-Hürde, mehr Dezentralisierung| 2026-03-21 |
| 8  | Waechter-KI: Phi-3-mini 4-bit         | Läuft auf 4GB RAM, kein GPU nötig               | 2026-03-21 |
| 9  | Blockchain: Kaspa mit Silverscript    | Einzige PoW-Chain mit diesen Fähigkeiten        | 2026-03-21 |
| 10 | Föderiertes Lernen: Fed-DART          | Datenschutzkonform, nur Gradienten              | 2026-03-21 |
| 11 | DSGVO: nicht anwendbar                | Keine personenbezogenen Daten on-chain          | 2026-03-21 |
| 12 | Validator Quorum: 67% (2/3-Mehrheit)  | Balance zwischen Sicherheit und Geschwindigkeit | 2026-03-21 |
| 13 | Abstimmung: Commit-Reveal + Salted    | Verhindert Absprachen kryptografisch            | 2026-03-21 |
| 14 | Anti-Sybil: Quadratic Voting (Rep^2)  | Mathematisch bewiesen (Buterin 2019)            | 2026-03-21 |
| 15 | Reporter-Pool: 75% Light / 25% Honeypot| Zero-Days seltener, aber wertvoller             | 2026-03-21 |
| 16 | Guardian hybrid routing: 8B default, 70B escalation <0.70 | guardian-economics.html documents this | 2026-03-22 |
| 17 | Ensemble voting: 5+ 8B nodes = alternative to 1x 70B | Reduces centralization risk | 2026-03-22 |
| 18 | Guardian Pooling: on-chain PROM split for shared 70B | Lowers entry from $60k to ~$6k per operator | 2026-03-22 |

---

## TOKEN-KLARSTELLUNG (KRITISCH – Claude Code immer beachten)

```
ValidatorStaking Contract:
  - tx.value = KAS (Kaspa nativer Token)
  - MIN_STAKE_KAS = 10.000 KAS
  - Slashing = KAS-Verlust

GuardianReputation Contract:
  - Kein finanzielles Staking
  - Reputation = uint64 (0 - 100000, 10000x skaliert, 10000 = 1.0)
  - PROM wird durch akzeptierte Vorschläge VERDIENT

DevIncentivePool Contract:
  - Auszahlungen in PROM
  - 5% der jährlichen PROM-Emission
  - Nur per DAO-Vote freigebbar
```

---

## TOKENOMICS (Referenz)

| Empfänger           | Anteil | Jahr 1        |
|---------------------|--------|---------------|
| Validators          | 40%    | 8.000.000 PROM|
| Guardians           | 30%    | 6.000.000 PROM|
| Reporter (gesamt)   | 20%    | 4.000.000 PROM|
|   └ Light Clients   | 15%    | 3.000.000 PROM|
|   └ Honeypot        | 5%     | 1.000.000 PROM|
| Dev Pool            | 5%     | 1.000.000 PROM|
| Community           | 5%     | 1.000.000 PROM|
| **GESAMT**          | 100%   |**20.000.000 PROM**|

---

## AUTO-TUNING PARAMETER (Startwerte)

| Parameter             | Startwert | Ziel                        |
|-----------------------|-----------|-----------------------------|
| MIN_STAKE_KAS         | 10.000    | 50–200 aktive Validators    |
| MIN_GUARDIAN_REP      | 0.3       | 200–1000 aktive Guardians   |
| MIN_CONFIDENCE_KI     | 0.85      | False-Positive-Rate < 0.5%  |
| VALIDATOR_CONSENSUS   | 0.67      | Stabile Regelannahme        |
| REWARD_BASE           | 100 PROM  | 100–200 Vorschläge/Tag      |
| SLASHING_SIMPLE       | 5%        | Fehlverhalten abschrecken   |
| SLASHING_COLLUSION    | 20%       | Kollusion unmöglich machen  |
| CHALLENGE_PERIOD      | 86400s    | 24 Stunden                  |

---

## CODE-STANDARDS (Claude Code muss immer einhalten)

### Rust
- `cargo fmt` vor jedem Commit
- `cargo clippy -- -D warnings` (keine Warnungen erlaubt)
- `cargo test` muss 100% grün sein
- Jede public Funktion: Rustdoc-Kommentar
- Mindest-Coverage: 80%

### Silverscript
- Kompilierung ausschließlich über den gepinnten upstream `silverc`-Stand und
  `scripts/smoke_silverc_artifacts.py`; der Compiler führt kein Netzwerk-Deploy aus
- Netzwerkpfad: geschlossene Deployment-Profile plus repository-eigener keyless
  Toccata-v1 Operator; externe Signaturen und bestätigte Evidence bleiben Pflicht
- Alle Structs aus SCHEMA.md verwenden
- Keine Magic Numbers – immer benannte Konstanten
- Jede Funktion: Kommentar mit Zweck

### Python (Guardian-Node, Scripts)
- Black Formatter
- Pylint Score >= 8.0
- Type Hints überall
- Docstrings für alle Klassen und Funktionen

### Allgemein
- Keine TODO-Kommentare im Code (in TODO.md stattdessen)
- Alle Fehler: in ERRORS.md dokumentieren
- Nach jedem Modul: AUDIT.md-Eintrag erstellen
- Git-Commits: `feat:`, `fix:`, `test:`, `docs:` Präfixe

## SEO / GEO / AI ANCHOR CHECKLIST
Every new HTML page MUST have before commit:
1. `<title>` — specific, descriptive, under 60 chars
2. `<meta name="description">` — under 155 chars, keyword-rich
3. `<meta property="og:*">` — 5 Open Graph tags minimum
4. `<script type="application/ld+json">` — Schema.org structured data
5. `<meta name="ai-summary">` — one-sentence AI-readable summary
6. `<link rel="canonical">` — correct self-referencing URL
7. Entry in sitemap.xml with correct lastmod date
8. llms.txt updated if new major content section added

9. Mobile nav burger menu — required on every new HTML page

This checklist is mandatory. No new page goes live without it.

## PFLICHT NACH JEDER ABGESCHLOSSENEN AUFGABE

0. Bei JEDER neuen HTML-Seite: SOFORT grep -L "application/ld+json"
   auf die neue Datei ausführen. Wenn leer → SEO/GEO-Checkliste
   vollständig anwenden BEVOR erster Commit.
   Kein HTML-Commit ohne Schema.org. Keine Ausnahme.

Nach JEDER Task — egal ob Sprint, Bugfix, oder Docs-Update:
1. memory/STATUS.md aktualisieren (Modul-Status)
2. memory/TODO.md: erledigte Tasks als [x] markieren
3. memory/AUDIT.md: Eintrag wenn Audit nötig
4. memory/CHECKPOINT.md: letzte Zeile "Last updated" aktualisieren
5. python3 scripts/autodidactic.py --action show_status ausführen
6. Erst DANN committen

Dies ist nicht optional. Es ist Teil jeder Task-Definition.

---

## BLOCKADEN (aktuell)

Sprint 9 ist nicht mehr durch Toccata, H-001-Verifikation oder das
Funding-/Identitäts-Gate blockiert. Der öffentliche non-promotable H-001
testnet-10 P2PK-Outpoint und die passende öffentliche Deployer-Identität sind
bestätigt. GH-17 ist auf exact main `9477fab` gemergt und remote grün; der
deterministische schema-v2 Request/Digest wurde daraus neu gebaut und live
preflight-verifiziert. Offen sind die explizit freizugebende externe
BIP340-Signatur, vollständige Operator-Verifikation, One-shot-Broadcast,
Bestätigung, `operator_record`-Receipt-Erfassung/-Verifikation und öffentliche
Evidence. Der Full-Rollout wartet zusätzlich auf die übrigen State-Contracts,
Metrics Oracle und Release Hardening.
Rusty-Kaspa Workspace-Dependencies sind seit 2026-07-07 auf `v2.0.1` gepinnt.
Core Dev benötigt: Apple Developer Account + Google Play Account (vor Sprint 13).

---

## ENTSCHEIDUNGSLOG

| Datum      | Entscheidung                          | Von        | Begründung                        |
|------------|---------------------------------------|------------|-----------------------------------|
| 2026-03-21 | KAS/PROM getrennt                     | Dev-Review | Validator staken KAS, nicht PROM  |
| 2026-03-21 | LLaMA 3 8B als Fallback               | Dev-Review | Niedrigere Hardware-Hürde         |
| 2026-03-21 | Reporter-Pool 75%/25% aufgeteilt      | Dev-Review | Zero-Days klarer bewertet         |
| 2026-03-21 | Kein Emergency-Stop                   | Core Dev   | Bewusstes Dezentralisierungs-Feature|
| 2026-03-21 | Whitepaper v4 = produktionsreif       | Dev-Review | 10/10 Audit-Ergebnis              |
| 2026-03-22 | Deployment-Ziel Aug/Sep 2026          | Core Dev   | Tägliche Arbeit, kein Zwischenstopp |
| 2026-03-22 | Mobile: Flutter (nicht React Native)  | Architect  | Hintergrund-Scanning braucht native Integration |
| 2026-03-22 | Guardian Installer: curl one-click script | Architect | Niedrigste Einstiegshürde für Server-Betreiber |
| 2026-07-15 | Geschlossene Deployment-Profile | Codex Audit | `full` bindet sieben Release-Fixtures und Metrics Oracle; H-001 bindet nur den non-promotable testnet-10 Canary ohne Oracle-Key |
| 2026-07-16 | Signed-shape Fee/Mass-Floor vor externer Signatur | Codex Audit | Pinned v2.0.1 Relay-Floor plus konservativer Overall-Mass-Floor werden in Signing-Request Schema v2 gebunden; alte Requests werden verworfen |
| 2026-07-16 | PeerId bleibt Transportmetadatum | Codex Audit | Persistente libp2p Identitaet, Relay, AutoNAT und DCUtR duerfen niemals Guardian-Mitgliedschaft, BIP340-Key-Zuordnung, Reputation, Stake oder Rewards autorisieren |
| 2026-07-26 | ThreatHint-v2 Binding bleibt data-only | Codex + Kimi Review | Exakter Envelope/Manifest/Network/Domain/Public-Input-Abgleich ist keine Groth16-Verifikation oder Rollout-Freigabe |
| 2026-07-26 | Raw Manifest SHA-256 ist separater Trust Anchor | Codex + Kimi Review | Exakte Manifest-Bytes werden vor dem Parsen gehasht; Source-/Key-Hashes bleiben inerte Assertions |
| 2026-07-26 | v2 Preflight konsumiert keine Approval | Codex Sol + Kimi Review | Strukturelle Proof-Bindung und Bundle/Approval-Kompatibilitaet sind keine Groth16-Akzeptanz; durable Consumption darf erst nach freigegebener Proof-Verifikation im selben Call-Pfad final atomar erfolgen |
| 2026-07-26 | v2 Verifier nutzt feste owner-only Bundle-Dateien | Codex Sol + Kimi Review | `verify-v2` lädt `relation-source.bin` und `verifying-key.bin` als feste Manifest-Geschwister, bindet Größe/SHA-256 und lädt zur Laufzeit niemals einen Proving Key; Produktionsrelation, Keys und Ceremony bleiben separate Freigaben |
| 2026-07-27 | v2 Verifier-Komposition bleibt nicht konsumierend | Codex Sol + Kimi Review | Ein owner-gepinnter Executable-Hash und dieselben Policy-Anker verbinden Python-Preflight und `verify-v2`; der Receipt bleibt data-only, SQLite/Approval-Consumption und Produktionsfreigabe bleiben ausserhalb |
| 2026-07-27 | v2 Acceptance konsumiert erst nach verifiziertem Preflight | Codex Sol + Kimi Review | Raw inputs only; exakte Network/Approver/Scope-Identitaet vor Ledger-Erstellung; Approval-ID/Commitment-Bindung vor dem finalen atomaren Consume; Produktionsartefakte und externe Effekte bleiben separate Gates |
| 2026-07-27 | v2 Promotion bleibt owner-policy Mechanik | Codex Sol + Kimi Review | Exakte Platform/Format/Kind/Count-Restriktionen laufen vor derselben raw Acceptance; das schliesst lokales Pairing, aber keine semantische Privacy-, Authority-, Transport- oder Produktionsfreigabe |
| 2026-07-27 | Recoverable Outbox bleibt governance- und transaktionsgebunden | Codex Sol + Kimi Review | Ticket 011 deklariert owner-only Retention ohne Persistenz; ein echter Enqueue muss mit Approval-Consumption und High-Water in derselben SQLite-Transaktion committen, und ein Digest-Journal ist kein recoverable Outbox |
| 2026-07-27 | v2 Authority aktiviert erst durch gueltige signierte Nutzung | Codex Sol + Kimi Review | Ticket 012 pinnt Promotion-/Governance-/Retention-Digests, Identity, Epoch und Window erst im atomaren Consume; Same-Identity-Epochs duerfen nicht ueberlappen, Rotation per Key/Scope bleibt moeglich, und blosses Laden einer fehlerhaften Zukunftspolicy kann den Ledger nicht sperren |
| 2026-07-28 | Governed v2 Outbox teilt die Approval-Transaktion | Codex Sol + Kimi Review | Ticket 013 migriert nur governed Ledger auf Schema v3 und speichert den vollstaendigen kanonischen Bundle-Wire atomar mit Authority, High-Water und Consumption; volle Queue oder Enqueue-Fehler rollen alles zurueck |
| 2026-07-28 | Claim ist owner-local, lease-basiert und retention-begrenzt | Codex Sol + Kimi Review | Aeltester berechtigter Datensatz, intern erzeugtes opaques 32-Byte-Token, Recovery nach Restart/Lease-Ablauf und terminales Delete nur bei exakter Approval-ID/Token-Bindung; kein Worker oder externer Effekt |
| 2026-07-29 | v2 Completion speichert Ergebnis vor Work-Delete | Codex Sol + Kimi Review | Governed Schema v4 bindet Statement, Nonce, Bundle, Approval, Lease und Retention; eine atomare Completion speichert exakt ein kanonisches nicht-actionable Ergebnis und loescht erst danach den Outbox-Datensatz |
| 2026-07-29 | Reale v2 Analyse bleibt separates High-Risk-Ticket | Codex Sol + Kimi Review | Der Ticket-014-Worker nutzt nur einen deterministischen Test-Analyzer ohne LLM, YARA, Confidence oder should_submit; semantische/actionable Analyse braucht eigene Privacy-/Security-Freigabe |
| 2026-07-31 | H-001 exact-main Readiness-Refresh | Codex Audit | Exact main `143a8a0` reproduziert den akzeptierten `205e1ca` Handoff nach dem Dependency-Security-Fix bytegleich und revalidiert den öffentlichen UTXO; Signatur, Broadcast und Chain-Evidenz bleiben gesondert freizugeben |
| 2026-08-13 | ThreatHint-v2 Transport vertraut keinem impliziten Netzwerk | Codex Sol + Kimi Review | Der Library-Default bleibt leer und fail-closed; der betriebene Service verlangt ein explizites trusted network. Rust validiert vor owner-only IPC, Python validiert erneut und bezieht Session sowie Zeit aus separatem trusted local state. Peer-ID und Report-Nonce bleiben reine untrusted Transportmetadaten |

## 2026-07-29 — Windows-PE-Producer exact-main Reintegration

- Der lokale Windows-PE-`api_import`-Producer ist auf exact-main `12a08d4`
  reintegriert, aber nicht committed, gepusht, gemergt oder live.
- Exakte PE32/PE32+-Bytes und ein gepruefter Index sind die einzigen
  Caller-Eingaben. Scope bleibt fest `windows`/`pe`; malformed Tabellen,
  Ordinal-Imports und Werte ausserhalb der geschlossenen Grammatik failen
  geschlossen. Auswahl erfolgt erst nach bytegenauer Sortierung und
  Deduplizierung.
- Das Ergebnis bleibt immer `review_required_v1`. Library-Namen werden nie
  Observables. Es gibt keinen Pfad-, String-, Transport-, Proof-, Analyzer-,
  Wallet-, Chain- oder Promotion-Effekt.
- Der alte Dirty-Branch und `Prometheus-1.png` bleiben fremde, unberuehrte
  Arbeit. Publishing benoetigt eine getrennte Freigabe.

## 2026-07-30 — Windows-PE-Producer exact-main veroeffentlicht

- GH-121 wurde per geschuetztem PR #122 ohne Bypass als exact-main `2e3e1e1`
  gemergt. Prometheus CI `30493381824`, Security Audit `30493381812` und
  Pages `30493381150` sind auf diesem SHA erfolgreich.
- Die Parser-, Privacy- und Non-Goal-Grenzen bleiben unveraendert: 16 MiB,
  4096 Import-Deskriptoren, 4096 Thunk-Eintraege, ausschliesslich
  `review_required_v1`, keine Transport-, Proof-, Analyzer-, Wallet-, Chain-
  oder Promotion-Autoritaet.
- Der alte Dirty-Branch und `Prometheus-1.png` bleiben fremde, unberuehrte
  Arbeit.
