id: a4-client-runtime-gate-r2
status: ok
worker: claude
branch: agent/claude/a4-client-runtime-gate-r2
summary: |
  Module modules/client, MAP hop H1 (main.rs ThreatHint submit -> p2p.rs ThreatHintSubmitConfig).
  PRM-03 re-verified: RuntimeMode::parse/from_env mapped missing, empty and unknown
  PROMETHEUS_RUNTIME to Development, and p2p require_development only checked the lenient env value,
  so an unset or typo'd env allowed dev-only ThreatHint preflight/submit (identity creation + dial).
  Fix: runtime.rs has a single strict parser `try_parse` (the lenient `parse` now delegates to it, so
  other components behave as before) plus `explicit_from_env()`. p2p.rs `require_development` now
  delegates to `require_explicit_development(process_mode, mode)`: the process env must be exactly
  development (case-insensitive) and match the validated mode. Otherwise it rejects in validate(),
  before any hint read, identity mutation, DNS/socket/QUIC activity. v1 and v2 paths share the gate.
  No new parser, flag, wrapper, retry, protocol or map node; MAP hop/status is unchanged.
files:
  - modules/client/src/runtime.rs (try_parse, explicit_from_env, unit test)
  - modules/client/src/network/p2p.rs (fail-closed H1 gate, unit test)
  - modules/client/tests/threat_hint_p2p_loopback.rs (missing/empty/malformed added to pre-network rejection loop)
tests: |
  cargo fmt --check -> OK
  cargo test -p prometheus-client --lib -- runtime:: network::p2p:: -> 25 passed, 0 failed
    (new: runtime::tests::test_try_parse_rejects_missing_and_malformed_modes,
     network::p2p::tests::process_runtime_gate_fails_closed_unless_explicit_development)
  cargo test -p prometheus-client --test threat_hint_p2p_loopback --test threat_hint_v2_p2p_loopback -> 3+3 passed
  Negative control: with the old lenient env read restored temporarily, the loopback
  beta_and_mainnet_reject_before_network_activity test FAILED (missing env permitted the run); fix restored and re-run green.
  Not run (per brief, orchestrator): full client package tests, cargo clippy -D warnings.
risks: |
  The lib unit tests use a cfg(test) seam (process_runtime_mode -> Some(Development)) so existing
  tests stay env-independent. The real env path is covered by the pure-gate unit test and by the binary
  loopback tests (built without cfg(test)). Operators must now set PROMETHEUS_RUNTIME=development
  explicitly for threat-hint preflight/submit (the loopback fixtures and CLI tests already do).
  Other components (rule sync, AI/ZK stubs) keep the lenient default and are outside this brief.
security: Closes PRM-03 fail-open for H1 only. No secrets touched and no network, deploy or chain activity.
next: Orchestrator runs full prometheus-client tests and Clippy. Decide separately whether rule-sync/stub gates also need explicit mode.
