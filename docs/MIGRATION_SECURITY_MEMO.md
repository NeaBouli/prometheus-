# MIGRATION SECURITY MEMO
## Projekt: Prometheus ($PROM)
## Datum: 14.04.2026

### Was wurde gefixt
- .gitignore: .env und .env.* hinzugefuegt (fehlten)
- .gitleaks.toml erstellt (Kaspa Private Key, Generic API Key)
- .github/workflows/security-audit.yml (Gitleaks + Dependency Audit)
- Prometheus CI: black Formatierung in yara_generator.py korrigiert

### Bei Migration beachten
- [ ] Keine .env Dateien existieren aktuell — bei Deployment erstellen
- [ ] Pre-Hardfork Audit bei 92% — H-002 gefixt, wartet auf SSC (05.05.2026)
- [ ] Kaspa RPC nur auf localhost (ws://127.0.0.1:17210) — korrekt

### Benoetigte ENV-Variablen
- Keine aktuell definiert — Projekt nutzt config-basierte Konfiguration
- Bei Deployment: RPC-Endpoints und API-Keys als ENV-Vars einrichten

### Was NIE auf den Server darf
- Kaspa Private Keys oder Wallet-Dateien
- .secrets/ Verzeichnis

### Migrations-Reihenfolge
1. SSC Audit abwarten (05.05.2026)
2. Server-Umgebung aufsetzen (Kaspa Node + RPC)
3. ENV-Variablen konfigurieren
4. Security Audit Workflow verifizieren (GitHub Actions)
