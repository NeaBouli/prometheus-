id: bundle-v2-profile-separation
worker: claude
mode: implement
base: a58320a (security acceptance pending)
architecture_node: contracts/silverc -> compiled manifest -> silverc-deployer profile validation (MAP.md M1/MS-B)

Continue the delivered draft on a separate task branch. Separate immutable
historical H-001 v1 evidence validation from proposed bundle-v2 build/profile
validation at the existing profile-selection boundary. Do not build a parallel
deployer. Keep v2 draft/non-promotable. Operator integration is a later block.

Acceptance:
- Historical H-001 source, artifact, evidence and identity pins stay byte-exact.
- Validate v1 against its pinned historical bundle, not regenerated v2 outputs.
- Validate v2 against a distinct expectation/manifest; no silent fallback,
  implicit default, hash rebasing or accepting either profile hash.
- Negative tests reject cross-profile artifacts, altered v1 evidence, mixed
  bundles and unknown identifiers before signing/export/broadcast.
- Preserve fail-closed boundaries. No executable v2 deployment/promotion path
  while security, D5 and deployment acceptance gates remain open.
- Run full relevant runtime, semantic/mutation, profile, deployer, formatting,
  lint/type and public gates; report exact commands and actual results.
- Do not duplicate the scheduled a58320a CI run. Coordinate one exact-head run
  for the next completed head with Codex.
- Update MAP, PLAN, Bridge and concise report; commit on the task branch.

Guardrails: no contract logic, D1-D7 approval, tokenomics, slash, commit-reveal,
toolchain/proof pin changes; no wallets/signing, chain, production, hosts,
nested agents, main merge, deployment or external writes. Codex owns review
and integration. Report any required wider architectural change before building.
