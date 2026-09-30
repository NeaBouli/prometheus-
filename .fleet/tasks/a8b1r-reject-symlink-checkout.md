id: a8b1r-reject-symlink-checkout
worker: claude
mode: security fix verification
branch: agent/claude/a8b1r-reject-symlink-checkout
architecture_node: SilverC checkout path identity in scripts/verify_silverc_h001.py

Codex review found one remaining issue in A8b1: `require_checkout_root()` accepts a symlink because resolved paths compare equal. Reject a symlink checkout path before any git operation and add a focused regression using a valid canonical target repository reached through a symlink.

Touch only `scripts/verify_silverc_h001.py`, `scripts/test_verify_silverc_h001_checkout.py`, and the Fleet report. Run the complete A8b1 focused test file plus Ruff/Mypy. Do not change pins, origin rules, contracts, CI, evidence, or versions. Do not start another agent.
