id: a8b1r-reject-symlink-checkout
status: ok
worker: codex (bounded fallback after Claude returned no report/diff)
branch: agent/codex/prometheus-master-plan-20260927
summary: SilverC checkout path identity now rejects symlinks before git access; a canonical target repository reached through a directory symlink is covered by regression.
files: scripts/verify_silverc_h001.py; scripts/test_verify_silverc_h001_checkout.py
tests: python3 -m unittest scripts/test_verify_silverc_h001_checkout.py -> 27 passed; Ruff -> passed; Mypy -> passed; git diff --check -> passed
risks: Fresh-clone publication still relies on git clone's destination checks; no new version, artifact, or evidence was introduced.
security: Fixes Codex review finding; no secrets, network state, wallet, chain, deploy, or production action.
next: Continue A8b2 manifest/rebuild/locked-Cargo/CI wiring.
