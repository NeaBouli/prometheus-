# PROMETHEUS – SPRINT PLANUNG
# Detaillierter Sprint-Plan mit Tagesaufgaben für Claude Code
# Last Updated: 2026-03-21

---

## ÜBERSICHT

| Sprint | Ziel                      | Wochen | Status  | Abhängigkeiten        |
|--------|---------------------------|--------|---------|-----------------------|
| 0      | Setup & Testnet           | 1      | PENDING | -                     |
| 1      | Core Contracts            | 2      | PENDING | Sprint 0              |
| 2      | Light Client Basis        | 2      | PENDING | Sprint 0              |
| 3      | Phi-3-mini Integration    | 1      | PENDING | Sprint 2              |
| 4      | Guardian Node             | 2      | PENDING | Sprint 1, 2           |
| 5      | Voting Mechanismus        | 1      | PENDING | Sprint 1              |
| 6      | End-to-End Integration    | 2      | PENDING | Sprint 1-5            |
| 7      | Audit Dashboard           | 1      | PENDING | Sprint 6              |
| 8      | Community & Förderung     | Parallel| PENDING | Whitepaper v4         |

**Gesamt: ~10-12 Wochen ab Sprint 1** (realistisch mit 2 Entwicklern)
**Ziel: Testnet-Launch Mai 2026, Mainnet 5. Mai 2026**

---

## ═══════════════════════════════════════════════
## SPRINT 0: SETUP & TESTNET
## Dauer: 1 Woche | Ziel: Infrastruktur steht
## ═══════════════════════════════════════════════

### Tag 1: Repository & Memory Layer

```bash
# Schritt 1: Repo-Struktur anlegen
mkdir -p prometheus/{memory,scripts,modules/{contracts,client,guardian-node,validator-node,web},tests,.github/workflows}

# Schritt 2: .gitignore
cat > .gitignore << 'EOF'
.secrets/
/tmp/
target/
__pycache__/
*.pyc
.env
node_modules/
*.enc
EOF

# Schritt 3: Alle memory/-Dateien aus Setup-Paket einspielen
cp memory-setup/* memory/

# Schritt 4: Scripts einspielen
cp scripts-setup/* scripts/
chmod +x scripts/*.py
chmod +x claude-code-start.sh

# Schritt 5: Initial commit
git add .
git commit -m "feat: Initial memory layer and project structure"
git push origin main
```

**Erwartetes Ergebnis:** Repository öffentlich auf GitHub, memory/-Dateien sichtbar.

---

### Tag 2: Kaspa Testnet-10-Node

```bash
# Schritt 1: rusty-kaspa installieren
# Ubuntu/Debian:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

git clone https://github.com/kaspanet/rusty-kaspa.git
cd rusty-kaspa
cargo build --release -p kaspad

# Schritt 2: Testnet-10-Node starten
./target/release/kaspad \
    --testnet \
    --netsuffix=10 \
    --utxoindex \
    --rpclisten 0.0.0.0:16210 \
    --rpclisten-borsh 0.0.0.0:17210

# Schritt 3: Verbindung testen
./target/release/kaspa-wrpc-server-client \
    --url ws://127.0.0.1:16210 \
    --cmd "getBlockDagInfo"

# Erwartet: JSON mit networkName: "kaspa-testnet-10"
```

**Erwartetes Ergebnis:** Node läuft, synct Testnet-10-Blöcke.

---

### Tag 3: Silverscript Compiler

```bash
# Schritt 1: ssc installieren (aus rusty-kaspa Repository)
cd rusty-kaspa
cargo build --release -p ssc

# Schritt 2: PATH setzen
export PATH=$PATH:$(pwd)/target/release
echo 'export PATH=$PATH:/path/to/rusty-kaspa/target/release' >> ~/.bashrc

# Schritt 3: Hello-World Contract schreiben
cat > /tmp/hello.ss << 'EOF'
contract HelloWorld {
    function greet() -> string {
        return "Prometheus is live";
    }
}
EOF

# Schritt 4: Kompilieren
ssc compile --testnet /tmp/hello.ss

# Erwartet: Kompilierung erfolgreich, output: hello.kas
```

**Erwartetes Ergebnis:** ssc Compiler funktioniert, Hello-World kompiliert.

---

### Tag 4: Erster Contract auf Testnet

```bash
# Schritt 1: Testnet-Wallet erstellen
./target/release/kaspa-wallet create --testnet

# Schritt 2: Testnet-KAS holen (Faucet)
# https://faucet-testnet-10.kaspa.org (falls verfügbar)
# Alternativ: Mining auf Testnet

# Schritt 3: Hello-World Contract deployen
ssc deploy --testnet --node ws://127.0.0.1:16210 hello.kas

# Schritt 4: Contract-Adresse in STATUS.md eintragen
python3 scripts/autodidactic.py --action update_status \
    --module "Hello-World Contract" \
    --status DONE \
    --address "<contract-adresse>"
```

**Erwartetes Ergebnis:** Erster Contract on-chain auf Testnet-10.

---

### Tag 5: GitHub Actions & CI/CD

```yaml
# .github/workflows/ci.yml
name: Prometheus CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  rust-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          components: rustfmt, clippy
      - name: Format Check
        run: cargo fmt --check
      - name: Clippy
        run: cargo clippy -- -D warnings
      - name: Tests
        run: cargo test

  python-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install black pylint
      - name: Format Check
        run: black --check scripts/
      - name: Pylint
        run: pylint scripts/ --fail-under=8.0

  memory-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Memory Integrity Check
        run: python3 scripts/check_memory_integrity.py
```

**Erwartetes Ergebnis:** GitHub Actions läuft durch, alle Checks grün.

---

### Sprint 0 Abschluss-Checkliste

```
[ ] Repository-Struktur auf GitHub
[ ] Alle memory/-Dateien committed
[ ] Testnet-10-Node läuft und synct
[ ] ssc Compiler funktioniert
[ ] Hello-World Contract auf Testnet deployed
[ ] Contract-Adresse in STATUS.md
[ ] GitHub Actions CI/CD grün
[ ] AUDIT.md: Sprint 0 als PENDING_AUDIT markiert
```

---

## ═══════════════════════════════════════════════
## SPRINT 1: CORE CONTRACTS
## Dauer: 2 Wochen | Ziel: Alle 6 Contracts deployed
## ═══════════════════════════════════════════════

### Woche 1: ValidatorStaking + GuardianReputation

**Täglich:**
- Morgens: MEMO.md + ERRORS.md lesen
- SCHEMA.md für Struct-Definitionen verwenden
- Nach jedem Contract: Unit-Tests schreiben
- Abends: STATUS.md aktualisieren

**ValidatorStaking.ss (Tag 1-3):**
```
Funktionen: register, commitVote, revealVote, slash, unstake
Tests:
  - test_register_validator_success
  - test_register_validator_insufficient_stake
  - test_commit_reveal_cycle
  - test_slash_on_invalid_reveal
  - test_cooldown_enforcement
  - test_kas_not_prom (KAS/PROM Trennung!)
  - test_double_vote_detection
  - test_collusion_detection
  - test_bond_calculation
  - test_auto_tuning_integration
Audit: an Claude senden nach Tag 3
```

**GuardianReputation.ss (Tag 4-5):**
```
Funktionen: register, submitContribution, votingPower, proposalAccepted/Rejected
Tests:
  - test_register_guardian_success
  - test_sybil_resistance (PoW-Check)
  - test_voting_power_quadratic
  - test_reputation_increase_on_accept
  - test_reputation_halving_on_reject
  - test_voting_right_revocation
  - test_compute_power_minimum
  - test_8b_vs_70b_model_type
Audit: an Claude senden nach Tag 5
```

### Woche 2: Remaining Contracts

**GovernanceAutoTuning.ss (Tag 1-2):**
```
Funktionen: auto_tune, get_parameter, set_parameter
Tests:
  - test_fp_rate_increases_confidence
  - test_low_proposals_increases_reward
  - test_parameter_bounds_respected
  - test_weekly_execution_only
Audit: an Claude senden nach Tag 2
```

**DevIncentivePool.ss + CommunityDonations.ss + RuleStorage.ss (Tag 3-5):**
```
Alle deployten Contract-Adressen in STATUS.md
Integration-Test: Alle Contracts interagieren korrekt
Finales Audit: Alle Contracts gemeinsam an Claude
```

---

## ═══════════════════════════════════════════════
## SPRINT 2-7: (Kurzübersicht)
## Vollständige Tages-Pläne werden zu Sprintbeginn generiert
## ═══════════════════════════════════════════════

### Sprint 2: Light Client (Woche 4-5)
```
Tag 1-2: connection.rs + krc20.rs (Kaspa-Integration)
Tag 3-4: scanner.rs + heuristic.rs (Security-Engine)
Tag 5:   p2p.rs Grundgerüst
Tag 6-7: zk_proof.rs
Tag 8-9: Tauri-UI Shell
Tag 10:  Integration-Tests
```

### Sprint 3: Phi-3-mini (Woche 5, parallel)
```
Tag 1-2: Modell herunterladen, quantisieren (4-bit ONNX)
Tag 3-4: phi3.rs + detection.rs
Tag 5:   federated.rs + Tests
```

### Sprint 4: Guardian Node (Woche 6-7)
```
Tag 1-2: Docker-Setup (8B zuerst)
Tag 3-4: llm_server.py + yara_generator.py
Tag 5-6: analyzer.py + reputation/
Tag 7-8: Guardian ↔ Validator Kommunikation
Tag 9-10: Tests
```

### Sprint 5: Voting (Woche 7)
```
Tag 1-2: Commit-Reveal in Silverscript
Tag 3:   Salted Voting
Tag 4:   Bond-System
Tag 5:   Voting-Tests
```

### Sprint 6: E2E Integration (Woche 8-9)
```
Vollständiger Durchlauf des Bedrohungslebenszyklus
Performance < 60 Sekunden
Security-Tests (Sybil, Collusion, Frontrunning)
```

### Sprint 7: Dashboard (Woche 9)
```
React-App, Live-Feed, Statistiken
Dev-Grants-Transparenz
```

---

## SPRINT ÜBERGABE-PROTOCOL

Nach jedem Sprint:
1. Alle Module in AUDIT.md als PENDING_AUDIT markieren
2. Core Dev informieren: "Sprint X abgeschlossen, bereit für Audit"
3. Core Dev schreibt an Claude: "Auditiere Sprint X"
4. Claude prüft, schreibt Ergebnis in AUDIT.md
5. Bei ACCEPTED: Nächsten Sprint starten
6. Bei NEEDS_CHANGES: Änderungen einarbeiten, erneut auditieren
