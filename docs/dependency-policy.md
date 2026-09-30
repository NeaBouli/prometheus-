# Dependency Policy

Status: active (GH-279 / PRM-09). Scope: third-party dependencies of the Rust
workspace and the Guardian Python environment. This policy governs how versions
are chosen and changed; it grants no production, deployment, or chain authority.

## Ownership

- The repository maintainers own every dependency pin. In the fleet workflow the
  orchestrator (Codex) approves and merges dependency changes; workers may only
  propose them on their own branches.
- A dependency change is its own reviewed change. It is never bundled with a
  security fix, a feature, or a contract change, so that each can be reverted
  independently.

## Rust workspace

- Rusty Kaspa and SilverScript are pinned by the machine-readable policy
  [`docs/architecture/toolchain-pins.json`](architecture/toolchain-pins.json),
  enforced by `scripts/verify_toolchain_pins.py` (CI job "Toolchain Pin Policy").
  An upgrade must update `Cargo.toml`, `Cargo.lock`, and the policy's active pins
  in the same change. The threat-proof artifact identity pins change only with a
  new proof-artifact identity.
- All Cargo builds in CI use `--locked`; `cargo audit` runs in the Security Audit
  workflow.

## Guardian Python environment

- `modules/guardian-node/requirements.txt` lists every direct dependency as an
  exact `name==version` pin. No floors, ranges, URLs, editable installs, index
  options, or markers.
- `modules/guardian-node/requirements-lock.txt` is the generated, fully
  hash-pinned closure for Python 3.11 (universal markers). It is regenerated only
  with the command recorded in its header, never edited by hand.
- Supported installation path:

  ```bash
  python -m pip install --require-hashes --only-binary :all: -r requirements-lock.txt
  ```

  Only prebuilt wheels are supported. This also excludes the known `coincurve`
  21.0.0 source-distribution packaging defect; source builds are unsupported.
- `scripts/verify_guardian_python_deps.py` (CI, job "Python Guardian") fails
  closed if a direct pin is not exact, a locked package lacks a SHA-256 hash, the
  lock drifts from a direct pin, the lock contains index/URL/option lines, or the
  `yara-x` pin differs from the engine version enforced at runtime
  (`jaeger/yara_semantic_quality.py`). `pip-audit` audits both files in the
  Security Audit workflow.

### Current deliberate pins

| Package | Pin | Reason |
|---|---|---|
| `yara-x` | `1.4.0` | Runtime-enforced exact engine version for the compile-only rule validator and the semantic quality corpus. Newer releases may change rule semantics; an upgrade needs its own change with the semantic-quality regression corpus re-run and reviewed. No known advisory against 1.4.0 (pip-audit clean). |
| `coincurve` | `21.0.0` | x-only public-key validation for signed ballots and membership. Wheels only (see above). |
| `httpx` | `0.28.1` | Loopback-only vLLM client (`trust_env=False`). Previously an open floor (`>=0.25.0`). |

## Updating a Python dependency

1. Change the exact pin in `requirements.txt` (one purpose per change).
2. Regenerate the lock with the header command (uv 0.11.x).
3. In a fresh Python 3.11 virtual environment, install with the supported
   command, then run `pip check`, the full Guardian test suite, Black, Pylint,
   `pip-audit -r requirements-lock.txt`, and `scripts/verify_guardian_python_deps.py`.
4. For `yara-x`, also update `PINNED_YARA_X_VERSION` and review the semantic
   quality corpus results before the change is proposed.
