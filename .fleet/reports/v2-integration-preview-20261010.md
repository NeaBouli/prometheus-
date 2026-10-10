# C2 Current-Main Integration Preview

Status: assembled; exact-head hosted integration and Draft publication pending.
Security: release/main integration HELD. Owner: Codex; Claude owner-paused.
Node: MAP M1/MS-B, contract -> registry -> operator -> observed D5 -> closed gate.
Base:eecbaf5731b6a0e2f3a77aebe8f42e97cf1daf47.
Reused worker:3e94ce0fa81591d2a0e23758dfc46a735a8b8a92.
Brief: .fleet/tasks/v2-integration-preview-20261010.md.

## Integration Scope

Tree-to-tree inventory found117 differences, not311 paths suggested by shared
ancestry before squash merges.51 source/test/workflow paths imported, no
duplicate worker implementation.49 remain byte-exact C2; two bounded deltas:

- CI explicitly runs existing scripts.test_silverc_genesis_binding_draft tests.
- validate_artifact's existing JSON object gets a dict[str, Any] annotation;
  no runtime logic, validation, artifact or signature behavior changes.

Source families: modules/contracts/silverc (v2 draft plus frozen h001-v1),
modules/silverc-deployer, validator cooldown constant, bundle/operator/receipt/
evidence/profile/manifest/runtime/D5 scripts and tests; .github/workflows/ci.yml.
Required D5 design/MAP/proposal/runbook pointers added/reconciled. Current main
public README/HTML/llms/ledger/claim verifiers/SW/audit reports/K2 retained.
Task-only PLAN/Bridge/Memory/report/brief/catalog addenda preserve history.

Relative to main, the candidate contains C2's new draft contract sources and
v2 compiled expectation. These are imported, not newly designed here. Rust
release pins and historical H-001 sources/manifest/archive remain v1 unchanged.
No additional compiled-source/crypto/trust-policy revision beyond C2.

## Actual Checks And Limitations

| Command / check | Actual result |
| --- | --- |
| Parent-owned mechanical git-diff/apply and blob identity checks | PASS51 initial exact C2 blobs; no unrelated path import |
| Parent-owned v2-preview static harness (private path omitted) | PASS49 exact C2 blobs, only2-line CI glue/1 annotation; retained main paths, append-only records, seven historical sources/provenance |
| ruff check on registry/D5/profile/early-gate/receipt/artifact modules | All checks passed |
| mypy --config-file /dev/null --no-incremental --cache-dir=/dev/null --strict scripts/silverc_genesis_binding_draft.py scripts/smoke_silverc_artifacts.py | Success: no issues found in2 source files (empty-config notice); no repository plugin loaded |
| git diff --cached --check | NOT clean: one inherited frozen H-001 EOF blank line; preserved deliberately for exact historical bytes |
| git diff --check and staged check excluding that one immutable reproduction file | PASS for remaining delta |

Initial strict mypy reproduced the worker's inherited helper finding; the one
annotation resolves it, without replacing runtime shape checks. Earlier task
snapshots recording that finding remain historical. The full workspace is not
claimed globally type-clean from this scoped check.

No target-controlled local test/build/browser or dependency download. Full OS
execution isolation remains unavailable locally; actual required suites must
execute in the existing hosted CI, not be inferred from static checks.
No screenshots needed/claimed: this candidate changes no rendered web/mobile UI.

The historical source whitespace exception is not an assertion/CI weakening:
ValidatorStakingH001.sil is copied byte-exact from reviewed e6d5464. Removing
the final blank changes provenance/reproduction pins. No frozen file, artifact,
SHA, test expectation or gate is altered to conceal the global checker result.

## Prior Evidence Reused, Not Relabeled

C2 exact37988100086 CI and37988101662 Security pass with109 runtime cases,
including four new boundary cases. Earlier profile/early-gate/capture/closed-gate
reviews are scoped evidence, not full independent acceptance of this new tree.
K1 covered61549b1 only. This preview still needs its own exact-head109 runtime
cases, D5 units, bundle/early separation, complete v1 operator and full relevant
workspace/Guardian/claims/Memory/pin/Security gates. No duplicate manual dispatch.

Metadata PR292 is fully Done: exact candidate/main CI/Security/Pages pass;
three live byte matches, icon URLs200;273 explicitly closed after acceptance,
275/270 remain open. Completed own metadata worktree verified/archived552 files.
The project-wide public review baseline stays2026-10-09.

## Holds And Next Steps

Publish/test as a normal Draft PR only. Do NOT merge main, activate D5, select
source policy, change keys, collect chain evidence, sign, broadcast or deploy.
D1-D7 remain proposed; deployment constructors/cumulative-counter constraints,
governance-key topology, source/policy/client/full-independent acceptance and
rollout stay open. Codex Security NOT CONNECTED/NOT RUN is a separate prospective
pre-integration gate, not replaced by Actions Security Audit or bot status.
No source-transfer expansion to Kimi, new cost/access/production authorization
or private finding/operator data inferred. Full project/ACTIVE goal NOT_COMPLETE.

## Final Parent-Checker Reconciliation

The final rerun first failed because the parent checker still required the
audit catalog to be byte-identical, despite the scoped metadata-closeout
addendum. The checker now verifies that this additional coordination document
retains its complete main-branch prefix, like the other append-only records.
No source equality, historical pin, public-claim or target CI assertion was
removed or changed. The failed rerun is not counted as a pass.
