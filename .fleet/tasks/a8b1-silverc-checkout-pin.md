id: a8b1-silverc-checkout-pin
worker: claude
mode: implementation
branch: agent/claude/a8b1-silverc-checkout-pin
architecture_node: SilverC source checkout trust boundary in scripts/verify_silverc_h001.py

A8b produced no report or diff. Implement only the checkout/pin core in `scripts/verify_silverc_h001.py` plus one focused new unittest file. Keep the active commit unchanged.

Require the requested ref to be lowercase 40-hex and equal the workspace `silverscript-lang` rev parsed structurally from root Cargo.toml. For an existing checkout require the canonical upstream origin and a clean tree; after checkout require exact HEAD equality. Temporary probe handling must restore a clean tree. Fail closed with no local path/content leakage.

Do not edit preflight, smoke, CI, Cargo.lock, contracts, evidence, defaults, or versions. Run focused tests and existing relevant script tests. Write the Fleet report; do not start another agent.
