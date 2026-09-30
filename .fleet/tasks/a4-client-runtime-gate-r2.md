# A4 retry — bounded runtime-gate patch

Use the architecture boundary, behavior, prohibitions, and security invariants
from `.fleet/tasks/a4-client-runtime-gate.md`.

The first attempt produced no report or diff. Keep this retry small:

1. Re-verify PRM-03 only inside `modules/client`.
2. Reuse the existing runtime parser and patch only the H1 pre-network gate.
3. Add focused unit regressions for missing, malformed, beta, mainnet, and the
   allowed development/Testnet-10 behavior.
4. Run `cargo fmt --check` and only the focused affected tests. The orchestrator
   will run full package tests and Clippy after integration.

Write `.fleet/reports/a4-client-runtime-gate-r2.md`; work only on
`agent/<worker>/a4-client-runtime-gate-r2`. No network, deploy, subagent, or
scope expansion.
