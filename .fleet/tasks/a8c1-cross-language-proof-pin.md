id: a8c1-cross-language-proof-pin
worker: claude
mode: security fix verification
branch: agent/claude/a8c1-cross-language-proof-pin
architecture_node: cross-language immutable relation identity in toolchain pin verifier

Codex review found A8c checks Rust threat-proof identity but not the matching Python Guardian relation parser. Extend only `scripts/verify_toolchain_pins.py` and `scripts/test_toolchain_pins.py` so the policy's immutable Rusty Kaspa tag/commit must occur exactly once and match in both `modules/threat-proof/src/lib.rs` and `modules/guardian-node/jaeger/relation_manifest_v2.py`.

Tests must reject Python tag drift, commit drift, missing/duplicate constants, malformed assignment form, and prove the real repo passes deterministically. Keep errors redacted and sorted. Run the complete toolchain-pin tests, verifier, Ruff, strict Mypy, and diff check. Do not modify either identity source, policy values, CI, manifests, lockfiles, versions, contracts, or evidence. Write the Fleet report; do not start another agent.
