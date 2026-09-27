id: plan-arch-map
status: ok
worker: kimi
branch: agent/kimi/plan-arch-map (commit 7bfd7a6, Basis exakt origin/main 32ca5f1)
summary: Karte neu angelegt (docs/architecture/ fehlte). Modul: modules/client ->
  modules/guardian-p2p -> modules/guardian-node; Hop H1-H8: ThreatHint-v1-Submission
  (main.rs::ThreatHintCommand::Submit -> network/p2p.rs::submit -> GuardianP2p ->
  UnixThreatHintIngress::forward -> threat_hint_service.py -> ThreatHintIngress ->
  threat-proof Verify -> SQLite-Outbox -> adapter.drain_once -> analyzer). Jeder Hop
  gegen Quelle geoeffnet. Module als built/partial/open/blocked/target klassifiziert,
  Duplikate/obsolete Stubs/nicht-bauen-Liste, Meilensteine M1-M6 mit Abhaengigkeiten,
  drei sichere naechste Knoten (GH-279, GH-280, GH-258/261 observe-only Slice).
files: docs/architecture/MAP.md, docs/architecture/map.puml, docs/architecture/main-path.puml (neu, 402 Zeilen, nur Doku)
tests: grep -n '^@start|^@end' docs/architecture/*.puml -> start/end-Tags balanciert (2 Diagramme map.puml, 1 Sequenzdiagramm);
  python3 scripts/check_public_documentation_hygiene.py -> passed (exit 0);
  python3 scripts/check_memory_integrity.py -> alle Checks bestanden (exit 0);
  plantuml nicht im PATH -> Quellen geschrieben, kein SVG-Render; Mermaid-Mindmap in MAP.md enthalten;
  kein Produktcode geaendert -> cargo/pytest nicht erforderlich; keine UI-Aenderung -> frontend-visual-release-gate n/a
risks: memory/TODO.md:288 markiert GH-272 als [~], HEAD ist aber der gemergte PR #281 (stale Zeile, nur Doku); analyzer.py enthaelt zwei Aufgaben (legacy heuristisch vs. verified v1) - als Befund auf der Karte, kein Umbau
security: none
next: Orchestrierung kann GH-279 (Dependency-Policy), GH-280 (Compose-Haertung) oder den GH-258/261-Review-Slice briefen; geblockte P0-Gates (Produktions-v2-Artefakte, sechs Deployments, Oracle) bleiben extern
