# Current-main / Held-v2 Integration Gate
status: partial
owner: Codex writing worker; Core owns review, commits, publication and hosted tests.
architecture: MAP M1/MS-B contracts -> frozen registry -> keyless deployer -> observed-only D5 -> closed acceptance.
first_parent: 24980e6ddaccfdfa8d09eddb78cbd3675d1afe67
merge_parent: 58d742aa7442ddc1663dbd9c3553e644bf0a7a2b
merge_base: eecbaf5731b6a0e2f3a77aebe8f42e97cf1daf47
pending_docs_parent: 649e4959586dd72b81a539df620802cecae9bfe3
merge_content_tree: 78577927a4dacafb7f6667fca59d077122c89215 (before this report).
final_index_tree: returned separately to Core; cannot embed the report-inclusive tree in itself.

## Merge And Resolution
- Command: git -c core.hooksPath=/dev/null merge --no-commit --no-ff 58d742aa7442ddc1663dbd9c3553e644bf0a7a2b
- Result: real merge, exit 1 for four content conflicts; MERGE_HEAD retained, no commit.
- Conflicts: .fleet/PLAN.md; docs/agent-bridge/ACTION_LOG.md; memory/STATUS.md; memory/AUDIT.md.
- Resolution: remove only the twelve conflict-marker lines; preserve both append tails, shared prefix once. AUDIT was an additional public coordination conflict, not a new audit or private packet read.
- Manual files: the four conflict files above and this report. Original task remains supplied/untracked, not staged.
- Automatic merge files: .github/workflows/{ci,security-audit}.yml; README.md; WHITEPAPER.md; docs/architecture/MAP.md; docs/validator-guide.md; index.html; whitepaper.html; modules/client/{README.md,src/runtime.rs}; scripts/test_toolchain_pins.py.
- Automatic added records: .fleet/{tasks,reports}/{ci-runner-pin,gh282-runtime-fail-closed,v1-v2-public-docs}-20261010.md.
- No manual source or MAP edit; automatic MAP combines current-main runtime/CI updates with held integration preview.

## Static Checks (Trusted Parsers / Git Only)
- PASS: 575 nondivergent tracked blob identities follow exact three-way parent selection; six divergent paths are only four conflicts, CI and MAP.
- PASS: all four resolutions exactly equal the two parent tails after their identical shared prefix, with base history unchanged.
- Initial overstrict raw-tail concatenation assertion rejected a duplicated shared post-base checkpoint; corrected shared-prefix-once assertion passes, no product change.
- PASS: all 50 held manifest source/test blobs unchanged; 49 exactly match worker blob pins, including frozen H-001 reproduction material; helper annotation retained.
- PASS: JSON manifest still DRAFT_PREVIEW_NOT_ACCEPTED, D5 UNCONDITIONALLY_CLOSED; existing Rust v1 pins and bundle/profile implementation preserved by blob identity.
- PASS: isolated PyYAML 6.0.3 safe_load composition equals held CI with exact-main runners and complete rust-check/rust-performance-check/pages-check jobs; 8 CI + 3 Security selectors ubuntu-24.04.
- Therefore held explicit bundle/D5/v1 operator steps and main GH282 parent sentinel/Development test profiles/PR297 hygiene registration coexist without manual workflow edits.
- PASS: stdlib AST confirms accept_state contains only docstring, input deletion and unconditional BindingError("NOT_CONFIRMED", ...); target modules never imported/executed.
- PASS: git diff --cached --check; zero unresolved index entries; HEAD and MERGE_HEAD match the exact parents above.
- Main-only public/product files retain exact parent blobs; original PR branches untouched. No execution/build/install/test, commit/push/CI, network/provider/host/wallet/deployment action.

## Pending / Risks
- Hosted combined-head suites NOT RUN: Rust workspace, runtime guards, 109 Silverc cases, v1 operator chain, D5/profile/public/security gates. Parent passes are not candidate evidence.
- Core must review all four conflict resolutions, automatic CI/MAP composition and security-relevant parent deltas, then make the first merge commit.
- Docs merge NOT STARTED: explicitly await Core authorization after MERGE_HEAD clears; acceptance/source/D1-D7/client/full-security/rollout holds unchanged.
- Worktree deliberately retained with resolved merged index and report staged for Core; no disposable outputs created or foreign edits reverted.
