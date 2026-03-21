# PROMETHEUS – ERROR LOG
# Bekannte Fehler und ihre Lösungen. Claude Code liest diese vor jeder Aktion.
# Format: | Datum | Modul | Fehler | Lösung | Status |
# Status: OPEN | RESOLVED | PATTERN (wiederkehrendes Muster)
# Last Updated: 2026-03-21

---

## BEKANNTE FEHLER-MUSTER (Claude Code: immer prüfen!)

Diese Muster sind aus anderen Projekten bekannt und sollen von Anfang an vermieden werden:

### PATTERN-001: KAS/PROM Verwechslung (KRITISCH)
```
Problem:  MIN_STAKE als PROM definiert, aber tx.value sendet KAS
Symptom:  Contract akzeptiert falsche Token, Staking schlägt fehl
Lösung:   IMMER MIN_STAKE_KAS (KAS) für Validators verwenden
          PROM wird NUR durch Leistung verdient, nie gestaked von Validators
Prüfung:  Vor jedem Silverscript-Commit: grep -n "MIN_STAKE" prüfen
```

### PATTERN-002: Silverscript Kompilierungs-Fehler
```
Problem:  ssc compile ohne --testnet auf Testnet-Contracts
Symptom:  Contract deployed aber inkompatibel mit Testnet-12
Lösung:   Testnet: ssc compile --testnet --network testnet-12
          Mainnet: ssc compile (ohne Flag)
Prüfung:  Immer Netzwerk-Flag überprüfen
```

### PATTERN-003: Rust Borrow-Checker bei async
```
Problem:  Arc<Mutex<T>> in async-Kontexten deadlockt
Symptom:  Programm hängt ohne Fehlermeldung
Lösung:   tokio::sync::Mutex statt std::sync::Mutex in async-Code
          RwLock für read-heavy Operationen
Prüfung:  cargo clippy findet viele dieser Fälle
```

### PATTERN-004: ZK-Proof Parameter-Mismatch
```
Problem:  Groth16-Parameter nicht zu Kaspa KIP-16 kompatibel
Symptom:  ZK-Proof wird on-chain abgelehnt
Lösung:   Parameter aus rusty-kaspa Repository verwenden
          Nicht eigene Parameter generieren
Prüfung:  kaspa-zk-params Crate verwenden
```

### PATTERN-005: IPFS CID Format
```
Problem:  CIDv0 (Qm...) statt CIDv1 (bafy...) verwendet
Symptom:  IPFS-Link nicht auflösbar, Regel-Content nicht ladbar
Lösung:   Immer CIDv1 (base32) verwenden: ipfs add --cid-version 1
Prüfung:  CID muss mit "bafy" beginnen
```

### PATTERN-006: Silverscript float64 Präzision
```
Problem:  Reputationsberechnung mit float64 hat Rundungsfehler
Symptom:  Reputation leicht unterschiedlich je nach Ausführungsreihenfolge
Lösung:   Für Vergleiche immer epsilon verwenden: abs(a - b) < 0.001
          Für Voting Power auf uint64 skalieren: (rep * 1000) as uint64
Prüfung:  Alle float64-Vergleiche mit epsilon
```

### PATTERN-007: libp2p Peer Discovery
```
Problem:  Peers werden gefunden, aber Verbindung schlägt fehl (NAT)
Symptom:  Netzwerk funktioniert lokal, nicht in Produktion
Lösung:   STUN/TURN Server für NAT traversal einrichten
          Kaspa-Bootstrap-Nodes als initiale Peers verwenden
Prüfung:  Integration-Tests mit simuliertem NAT
```

---

## FEHLER LOG (werden during Development befüllt)

| Datum | Modul | Fehler | Lösung | Status |
|-------|-------|--------|--------|--------|
| 2026-03-21 | Sprint 0 / ssc | KRITISCH: `ssc` (Silverscript Compiler) existiert nicht im rusty-kaspa Repo. Kein Package "ssc" im Workspace. Silverscript ist kein produktionsreifes Tool im Kaspa-Ökosystem (Stand März 2026). | BLOCKED — Core Dev muss klären: (a) Eigenen Compiler schreiben, (b) KRC-20/WASM-Contracts als Alternative, (c) Kaspa-Community-Fork mit ssc. Siehe AUDIT.md QUESTION FOR CLAUDE. | OPEN |
| 2026-03-21 | Sprint 0 / Testnet | MITTEL: Testnet-12 existiert nicht in rusty-kaspa v1.1.0. Nur Testnet-10 (netsuffix=10) wird unterstützt. Panic in params.rs:519. | Testnet-10 stattdessen verwendet. Alle Referenzen in MEMO.md und Contracts müssen auf Testnet-10 geändert werden. | RESOLVED |
| 2026-03-21 | Sprint 0 / kaspad | NIEDRIG: `--netsuffix 12` Syntax-Fehler. Kaspad erwartet `--netsuffix=12` (Gleichheitszeichen). | Korrekte Syntax: `--netsuffix=10` mit Gleichheitszeichen. | RESOLVED |

---

## FEHLER-KATEGORIEN

```
KRITISCH:  Verhindert Deployment / verletzt Architekturentscheidungen
HOCH:      Funktionalität eingeschränkt
MITTEL:    Edge-Case, selten auftretend
NIEDRIG:   Kosmetisch / Performance
```

---

## CLAUDE CODE ANWEISUNG

Vor jedem neuen Modul:
1. Diese Datei lesen
2. Alle PATTERN-00X prüfen
3. Wenn bekanntes Muster relevant: Lösung direkt anwenden
4. Neue Fehler sofort hier dokumentieren

Eintrag-Format für neue Fehler:
```
| YYYY-MM-DD | modul/datei.rs | Fehlermeldung (max 80 Zeichen) | Angewandte Lösung | RESOLVED |
```
