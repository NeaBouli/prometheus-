# GH282: fail-closed runtime selection

Status: In Progress. Owner: Codex. Base: d1ca321c4bf69d9f752c5ac8deab6794767f1387.
Existing MAP client hop: runtime selection -> security-stub guard -> development
ThreatHint/RuleSync/AI/proof boundaries. Issue282, separate from README honesty,
toolchain upgrades and held contract-v2 acceptance. No new module or API.

Files: modules/client/src/runtime.rs; .github/workflows/ci.yml (two existing
test steps only); modules/client/README.md; README.md; bounded Fleet/Bridge.

Enforce: missing, empty, invalid or unreadable environment cannot implicitly
enable Development. Keep the existing restrictive Beta fallback (not a Beta
deployment authorization) and unchanged explicit_from_env strict selection.
Only explicit development permits development stubs. Preserve accepted aliases,
Beta/Mainnet restrictions and development-only pre-network checks.

Regression: pure invalid/empty parser and stub-denial cases; existing real-binary
subprocess matrix removes/overrides the runtime env for missing/invalid/Beta/
Mainnet and exercises explicit-Development positive loopback paths. No shared
environment mutation in tests. Development suites declare their intended mode.

Acceptance: exact-head full hosted Workspace/Clippy/fmt/loopback/performance,
Guardian, claims/Memory/pin/contract and Security checks. No weakened assertion,
unsafe local target execution, model/network/production acceptance or new scan.
Scoped security review and owner-authorized review gates remain before adoption.
Publish as Draft first; do not close282 or promote v2 from fixtures/CI alone.

Routing: small central guard/config/glue patch; Claude paused; Kimi PR293 scope
extension still unapproved. No worker outage/fallback or duplicate implementation.
