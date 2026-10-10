# Current-main / Held-v2 Integration Gate
status: partial; hosted combined-head tests pending.
owner: Codex writing worker; Core owns review, commits, publication and hosted tests.
architecture: MAP M1/MS-B contracts -> frozen registry -> keyless deployer -> observed-only D5 -> closed acceptance.

## Stage 1: Main Merge (Reviewed And Committed By Core)
- Exact parents: 24980e6ddaccfdfa8d09eddb78cbd3675d1afe67 + 58d742aa7442ddc1663dbd9c3553e644bf0a7a2b; base eecbaf5731b6a0e2f3a77aebe8f42e97cf1daf47.
- Command: git -c core.hooksPath=/dev/null merge --no-commit --no-ff 58d742aa7442ddc1663dbd9c3553e644bf0a7a2b; exit 1, four append-only conflicts resolved by removing twelve marker lines.
- Conflicts: .fleet/PLAN.md; docs/agent-bridge/ACTION_LOG.md; memory/STATUS.md; memory/AUDIT.md (public coordination only).
- Prepared content tree78577927a4dacafb7f6667fca59d077122c89215; report-inclusive worker tree030be7423795724a8e8b500dd6d4dc5dedb53d62.
- Core reviewed all four exact unions, parent blobs and CI/MAP composition, then committed7abb76b9eb63f2be27ee81cbbcbc699ead4612a3; actual checkpoint tree969f74f3a8c577079b6ddfdf6fb76aaacceb9418.
- Prior PASS: 575 parent-derived nondivergent blobs; 50 held cohort blobs unchanged, 49 worker-exact; YAML retained 8+3 Ubuntu24 selectors, GH282 sentinel/profiles, PR297 hygiene and held bundle/D5/v1 steps.
- Prior PASS: stdlib AST unconditional NOT_CONFIRMED; frozen H-001 and Rust v1 pins retained; whitespace and zero unresolved entries. No target execution; Core review reported by explicit authorization.

## Stage 2: Authorized Exact Docs Merge (Uncommitted)
- Exact parents: HEAD7abb76b9eb63f2be27ee81cbbcbc699ead4612a3 + MERGE_HEAD649e4959586dd72b81a539df620802cecae9bfe3; base24980e6ddaccfdfa8d09eddb78cbd3675d1afe67.
- Command: git -c core.hooksPath=/dev/null merge --no-commit --no-ff 649e4959586dd72b81a539df620802cecae9bfe3; exit 1, two actual append-only conflicts.
- Conflicts/manual resolution: .fleet/PLAN.md and docs/agent-bridge/ACTION_LOG.md; remove six marker lines only, preserve both histories and the shared prefix once.
- Automatic exact-docs-parent blobs: docs/architecture/ms-b-contract-decisions.md; modules/contracts/silverc/README.md; .fleet/{tasks,reports}/msb-docs-reconciliation-20261010.md.
- Stage-2 manual files: two conflicts above and this report; no MAP/task append needed, no historical rewrite.
- Docs merge-content tree before report update: 5b680f5d970132f55cfca3bbd93d104886160ce5. Final report-inclusive staged tree returned separately (self-reference avoided).
- PASS Git metadata: 583 nondivergent entries follow exact three-way parent selection; only two divergent paths, both verified exact append-only unions.
- PASS closed changed-path set: only six docs/coordination files before report update; four imported nonconflict blobs exactly equal docs parent, modes preserved.
- PASS JSON/Git cohort: 49/50 held entries unchanged against Core checkpoint; sole exception is documentation README, exactly docs-parent blob. No source implementation delta.
- All other tracked blobs remain exactly Core checkpoint: source/artifacts, frozen v1, Rust manifest pins, UI/assets/public claims, CI/Security, runtime guards, MAP and Memory. No source reread or rebuild.
- Static-check harness corrected one expected filename typo (ms-b -> msb); corrected complete metadata check PASS, no target code involved.
- PASS git diff --cached --check, zero unresolved index entries, exact HEAD/MERGE_HEAD; no unstaged/foreign edit reverted. Original held branches unchanged.

## Pending / Risks
- Hosted combined-head suites NOT RUN: Rust workspace, runtime guards, 109 Silverc cases, v1 operator chain, D5/profile/public/security gates. Parent passes are not candidate evidence.
- Core reviews Stage 2 and commits; full independent acceptance/source/D1-D7/constructor/client/Codex Security/rollout holds unchanged, D5 closed and v2 non-promotable.
- Local hooks disabled only for merge to avoid repository execution; hosted CI/protection never disabled. No worker commit/push/tests/build/install/CI/nesting/network/provider/host/wallet/deployment action.
- Resolved staged index/MERGE_HEAD retained for Core; no disposable output created or cleanup needed.

Core Stage-2 review PASS: both exact coordination unions;320 retained source/UI/CI blobs; both reviewed documentation blobs exact. Core-only overbroad modules-directory assertion corrected to allow the explicit reviewed README; no product patch. Merge10393ae committed; combined-head hosted results still pending. Native worker closed; original held branches unchanged. Scoped static review COMPLETE/PARTIAL, not full-v2 acceptance.
