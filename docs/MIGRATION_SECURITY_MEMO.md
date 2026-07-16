# MIGRATION SECURITY MEMO
## Projekt: Prometheus ($PROM)
## Datum: 14.04.2026 (Status aktualisiert 16.07.2026)

### Was wurde gefixt
- .gitignore: .env und .env.* hinzugefuegt (fehlten)
- .gitleaks.toml erstellt (Kaspa Private Key, Generic API Key)
- .github/workflows/security-audit.yml (Gitleaks + Dependency Audit)
- Prometheus CI: black Formatierung in yara_generator.py korrigiert

### Bei Migration beachten
- [ ] Keine .env Dateien existieren aktuell — bei Deployment erstellen
- [x] Toccata/current-Silverc Audit — H-002 gefixt; H-001 Byte-Core,
      signed-int bounds, sieben Release-Fixtures und keyless Operator sind CI-verifiziert
- [ ] Reale Deployments bleiben auf externe Signaturen, bestaetigte Receipts,
      unabhaengige Chain-Evidence und exact-commit Release-Hardening begrenzt
- [ ] Kaspa RPC nur auf localhost (ws://127.0.0.1:17210) — korrekt

### Benoetigte ENV-Variablen
- Keine aktuell definiert — Projekt nutzt config-basierte Konfiguration
- Bei Deployment: RPC-Endpoints und API-Keys als ENV-Vars einrichten

### Was NIE auf den Server darf
- Kaspa Private Keys oder Wallet-Dateien
- .secrets/ Verzeichnis

### Migrations-Reihenfolge
1. Exakten Release-Commit und geschlossene Deployment-Profile verifizieren
2. Server-Umgebung aufsetzen (Kaspa Node + credential-freies TLS/RPC-Ziel)
3. Secrets nur ausserhalb des Repositories ueber den vorgesehenen Vault/HSM-Pfad konfigurieren
4. Prometheus CI, Security Audit und Pages fuer den exakten Commit verifizieren
5. Signatur, Broadcast, Receipt und Chain-Evidence als getrennte Freigabegates ausfuehren
