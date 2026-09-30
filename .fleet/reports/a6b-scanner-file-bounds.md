id: a6b-scanner-file-bounds
status: ok
worker: claude
branch: agent/claude/a6b-scanner-file-bounds
summary: |
  PRM-05 re-verified as valid: YaraScanner::scan_file used unbounded fs::read and
  AnomalyDetector::analyze_file used unbounded tokio::fs::read. Module/hop per MAP.md:
  modules/client "dev scanner" (security/scanner.rs::YaraScanner) and "AI + ZK stubs"
  (ai/detection.rs), hop = local file read -> scan_bytes/analyze_bytes. Fix: open the
  file and read through take(LIMIT + 1), then reject empty and over-limit input with
  generic errors before scanning. Limits: MAX_SCAN_FILE_BYTES and MAX_ANALYSIS_FILE_BYTES,
  16 MiB each (one per owning module). No metadata-only check; the read itself is capped,
  so growing files and special files (/dev/zero) cannot bypass it. scan_bytes and
  analyze_bytes, parser, model, rule ingest, CLI and docs are unchanged.
files:
  - modules/client/src/security/scanner.rs
  - modules/client/src/ai/detection.rs
  - .fleet/reports/a6b-scanner-file-bounds.md
tests: |
  New tests: scanner has empty, exact-limit, over-limit, /dev/zero and generic missing-file
  error tests; the existing test_scan_file covers the normal case. Detection has normal,
  empty, exact-limit, over-limit, /dev/zero and generic missing-file error tests. No
  existing assertion was changed.
  cargo fmt --all -- --check: OK. Focused `cargo test -p prometheus-client --lib -- scanner
  detection`: 43 passed. Full `cargo test -p prometheus-client`: every suite ok, 0 failed
  (lib 189 passed, 2 ignored as before). `cargo clippy -p prometheus-client --all-targets
  -- -D warnings`: clean.
risks: |
  Behavior change: empty files now return an error instead of a clean ScanResult or
  DetectionResult, and files over 16 MiB are rejected. No in-repo production caller of
  scan_file or analyze_file exists. A FIFO path still blocks at open() (OS semantics); that
  is not an allocation risk and is out of scope.
security: PRM-05 (unbounded file-read allocation) fixed on this branch; no new finding.
next: Orchestrator review and integration; PRM audit tracker can mark PRM-05 fixed after merge.
