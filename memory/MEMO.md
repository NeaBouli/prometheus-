# PROMETHEUS – PERSISTENT MEMORY (MEMO)
# Version: 4.0
# Last Updated: 2026-03-21
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
| 2  | PROM = Reputations-/Governance-Token  | Guardians verdienen PROM durch Leistung         | 2026-03-21 |
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
- Kompilierung: `ssc compile --testnet` (Testnet), `ssc compile` (Mainnet)
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

---

## BLOCKADEN (aktuell)

Keine bekannten Blockaden.

---

## ENTSCHEIDUNGSLOG

| Datum      | Entscheidung                          | Von        | Begründung                        |
|------------|---------------------------------------|------------|-----------------------------------|
| 2026-03-21 | KAS/PROM getrennt                     | Dev-Review | Validator staken KAS, nicht PROM  |
| 2026-03-21 | LLaMA 3 8B als Fallback               | Dev-Review | Niedrigere Hardware-Hürde         |
| 2026-03-21 | Reporter-Pool 75%/25% aufgeteilt      | Dev-Review | Zero-Days klarer bewertet         |
| 2026-03-21 | Kein Emergency-Stop                   | Core Dev   | Bewusstes Dezentralisierungs-Feature|
| 2026-03-21 | Whitepaper v4 = produktionsreif       | Dev-Review | 10/10 Audit-Ergebnis              |
