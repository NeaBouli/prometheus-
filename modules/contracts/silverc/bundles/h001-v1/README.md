# Frozen bundle `h001-v1` (reproduction material only)

Immutable copy of the release bundle whose `ValidatorStakingH001` canary was
confirmed on Testnet-10 on 2026-08-12. It exists only so the historical H-001
evidence can be re-validated byte-exactly after the fixture tree moved to the
proposed bundle v2. It is **not** a second maintained contract line: never edit,
fix or extend these files.

- Origin: `modules/contracts/silverc/*.sil` and the `FIXTURES` definition in
  `scripts/smoke_silverc_artifacts.py` at commit
  `e6d5464a8535a9a3095507501af7f8706c336258` (main after PR #285).
- `manifest.json` is the release manifest built from those sources with the
  pinned silverc `d25bd3427a093c17327ca3d6b9e1aa5f7688c863`; its canonical
  SHA-256 is `e6cec2aa…aefd`, the value recorded in
  `docs/evidence/gh-9-h001-public-evidence-2026-08-12.json`, and the
  deterministic archive SHA-256 is `4989f076…977d`.
- `provenance.json` pins every file; its own SHA-256 is pinned in
  `scripts/silverc_bundles.py`. Any change fails the registry.
