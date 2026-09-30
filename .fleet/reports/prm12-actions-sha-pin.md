id: prm12-actions-sha-pin (PRM-12 hygiene item "CI actions tag-pinned")
status: ok (hosted proof pending on next CI run)
worker: claude (Codex stand-in, solo)
summary: 22 `uses:` references in ci.yml and security-audit.yml pinned to full commit SHAs resolved 2026-09-30 via the GitHub API, human ref kept as comment: actions/checkout v7 → 3d3c42e5…, actions/setup-python v6 → ece7cb06…, Swatinem/rust-cache v2 (annotated tag dereferenced) → 6323deb1…, dtolnay/rust-toolchain 1.95.0 (branch; commit message "toolchain: 1.95.0") → 46817827…, gitleaks/gitleaks-action v3 → e0c47f4f….
tests: YAML parse OK; toolchain-pin and guardian-deps workflow tests OK; no script parses action refs. Hosted verification: the dispatched runs 36698349293/36698357152 test the previous head; the pin commit f737c7b needs one hosted run (next PR/dispatch).
remaining PRM-12 items (not done): deny_unknown_fields consistency in silverc-deployer file formats; CI self-attested governance JSON; Cargo.lock duplicates (upstream); bond overflow style; clock high-water runbook entry.
