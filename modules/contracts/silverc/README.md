# Current Silverscript Compatibility Fixtures

This directory contains contracts written for the current upstream `silverc`
toolchain from `kaspanet/silverscript`.

The legacy `.ss` files in `modules/contracts/` are Prometheus architecture
contracts from the pre-Toccata design phase. They use Solidity-like state
features such as `state map`, `msg.sender`, `tx.value`, `emit`, and `transfer`
that are not a direct 1:1 match for current upstream Silverscript syntax.

## ValidatorStakingH001.sil

`ValidatorStakingH001.sil` isolates the deploy-critical commit-reveal preimage:

```text
vote_byte(1) || salt_le(8) || block_height_le(8)
```

It is intentionally small. It proves the H-001 byte encoding with current
`silverc`/runtime before the full `ValidatorStaking.ss` state-machine port.

Run from the Prometheus repo root:

```bash
python3 scripts/verify_silverc_h001.py
python3 scripts/smoke_silverc_artifacts.py
```

The script uses `/tmp/prom-silverscript` and the pinned upstream ref
`d25bd3427a093c17327ca3d6b9e1aa5f7688c863` by default. Override with:

```bash
SILVERSCRIPT_REPO=/path/to/silverscript python3 scripts/verify_silverc_h001.py
SILVERSCRIPT_REF=<commit-or-tag> python3 scripts/verify_silverc_h001.py
SILVERSCRIPT_REPO=/path/to/silverscript python3 scripts/smoke_silverc_artifacts.py
PROMETHEUS_SILVERC_ARTIFACT_DIR=/tmp/out python3 scripts/smoke_silverc_artifacts.py
python3 scripts/smoke_silverc_artifacts.py --out-dir /tmp/out --archive /tmp/prometheus-silverc-artifacts.tar.gz
python3 scripts/preflight_silverc_deploy.py --archive /tmp/prometheus-silverc-artifacts.tar.gz --network sandbox --rpc-url ws://127.0.0.1:17210 --deployer-address kaspatest:qptestpreflight000000000000000000000000000000000 --metrics-oracle-pubkey 1111111111111111111111111111111111111111111111111111111111111111 --plan-out /tmp/prometheus-silverc-deploy-preflight.json --runbook-out /tmp/prometheus-silverc-deploy-runbook.md
python3 scripts/build_silverc_deploy_requests.py --archive /tmp/prometheus-silverc-artifacts.tar.gz --out-dir /tmp/prometheus-silverc-deploy-requests --network sandbox --rpc-url ws://127.0.0.1:17210 --deployer-address kaspatest:qptestpreflight000000000000000000000000000000000 --metrics-oracle-pubkey 1111111111111111111111111111111111111111111111111111111111111111 --request-set-out /tmp/prometheus-silverc-deploy-request-set.json --runbook-out /tmp/prometheus-silverc-deploy-requests.md
python3 scripts/verify_silverc_deploy_requests.py --archive /tmp/prometheus-silverc-artifacts.tar.gz --request-set /tmp/prometheus-silverc-deploy-request-set.json --requests-dir /tmp/prometheus-silverc-deploy-requests --summary-out /tmp/prometheus-silverc-deploy-request-verification.json --runbook-out /tmp/prometheus-silverc-deploy-request-verification.md
python3 scripts/build_silverc_deploy_operator_procedure.py --archive /tmp/prometheus-silverc-artifacts.tar.gz --request-set /tmp/prometheus-silverc-deploy-request-set.json --requests-dir /tmp/prometheus-silverc-deploy-requests --summary-out /tmp/prometheus-silverc-deploy-operator-procedure.json --runbook-out /tmp/prometheus-silverc-deploy-operator-procedure.md
python3 scripts/build_silverc_operator_receipts.py --archive /tmp/prometheus-silverc-artifacts.tar.gz --request-set /tmp/prometheus-silverc-deploy-request-set.json --requests-dir /tmp/prometheus-silverc-deploy-requests --orchestrator-results /path/to/public-external-deploy-results.json --operator-receipts-out /tmp/prometheus-silverc-operator-receipts.json --summary-out /tmp/prometheus-silverc-operator-receipts-summary.json --runbook-out /tmp/prometheus-silverc-operator-receipts.md
python3 scripts/verify_silverc_deploy_receipts.py --archive /tmp/prometheus-silverc-artifacts.tar.gz --receipts modules/contracts/silverc/deploy-receipts.sample.json --summary-out /tmp/prometheus-silverc-deploy-receipts-summary.json --runbook-out /tmp/prometheus-silverc-deploy-receipts.md
python3 scripts/verify_silverc_deploy_receipt_evidence.py --archive /tmp/prometheus-silverc-artifacts.tar.gz --receipts /path/to/operator-record-receipts.json --evidence /path/to/public-node-or-explorer-evidence.json --summary-out /tmp/prometheus-silverc-deploy-receipt-evidence-summary.json --runbook-out /tmp/prometheus-silverc-deploy-receipt-evidence.md
python3 scripts/stage_silverc_deployment_status.py --archive /tmp/prometheus-silverc-artifacts.tar.gz --operator-receipts /path/to/operator-record-receipts.json --status-out /tmp/prometheus-silverc-status-draft.json --snippet-out /tmp/prometheus-silverc-status-draft.md
python3 scripts/preflight_metrics_oracle_report.py --report modules/contracts/silverc/metrics-oracle-report.sample.json --plan-out /tmp/prometheus-metrics-oracle-preflight.json --runbook-out /tmp/prometheus-metrics-oracle-runbook.md
python3 scripts/build_metrics_oracle_tx_request.py --archive /tmp/prometheus-silverc-artifacts.tar.gz --report modules/contracts/silverc/metrics-oracle-report.sample.json --contract-instance-id sandbox:governance-auto-tuning-state-fixture-0001 --tx-request-out /tmp/prometheus-metrics-oracle-tx-request.json --runbook-out /tmp/prometheus-metrics-oracle-tx-request.md
python3 scripts/build_metrics_oracle_operator_procedure.py --archive /tmp/prometheus-silverc-artifacts.tar.gz --tx-request /tmp/prometheus-metrics-oracle-tx-request.json --summary-out /tmp/prometheus-metrics-oracle-operator-procedure.json --runbook-out /tmp/prometheus-metrics-oracle-operator-procedure.md
python3 scripts/verify_metrics_oracle_tx_result.py --archive /tmp/prometheus-silverc-artifacts.tar.gz --tx-request /tmp/prometheus-metrics-oracle-tx-request.json --tx-result /path/to/public-metrics-oracle-tx-result.json --summary-out /tmp/prometheus-metrics-oracle-tx-result-summary.json --runbook-out /tmp/prometheus-metrics-oracle-tx-result.md
python3 scripts/verify_metrics_oracle_tx_evidence.py --archive /tmp/prometheus-silverc-artifacts.tar.gz --tx-request /tmp/prometheus-metrics-oracle-tx-request.json --tx-result /path/to/public-metrics-oracle-tx-result.json --evidence /path/to/public-metrics-oracle-tx-evidence.json --summary-out /tmp/prometheus-metrics-oracle-tx-public-evidence-summary.json --runbook-out /tmp/prometheus-metrics-oracle-tx-public-evidence.md
python3 scripts/stage_metrics_oracle_status.py --archive /tmp/prometheus-silverc-artifacts.tar.gz --tx-request /tmp/prometheus-metrics-oracle-tx-request.json --tx-result /path/to/public-metrics-oracle-tx-result.json --status-out /tmp/prometheus-metrics-oracle-status-draft.json --snippet-out /tmp/prometheus-metrics-oracle-status-draft.md
python3 scripts/verify_release_hardening_evidence.py --evidence /path/to/public-release-hardening-evidence.json --expected-commit "$(git rev-parse HEAD)" --summary-out /tmp/prometheus-release-hardening-evidence-summary.json --runbook-out /tmp/prometheus-release-hardening-evidence.md
python3 scripts/build_silverc_operator_handoff.py --archive /tmp/prometheus-silverc-artifacts.tar.gz --out-dir /tmp/prometheus-silverc-operator-handoff --network sandbox --rpc-url ws://127.0.0.1:17210 --deployer-address kaspatest:qptestpreflight000000000000000000000000000000000 --metrics-oracle-pubkey 1111111111111111111111111111111111111111111111111111111111111111 --orchestrator-results /path/to/public-external-deploy-results.json --deploy-receipt-evidence /path/to/public-node-or-explorer-evidence.json --metrics-tx-result /path/to/public-metrics-oracle-tx-result.json --metrics-tx-evidence /path/to/public-metrics-oracle-tx-evidence.json --release-hardening-evidence /path/to/public-release-hardening-evidence.json
python3 scripts/audit_silverc_release_readiness.py --handoff-dir /tmp/prometheus-silverc-operator-handoff --summary-out /tmp/prometheus-silverc-release-readiness.json --runbook-out /tmp/prometheus-silverc-release-readiness.md
```

## ValidatorStakingState.sil

`ValidatorStakingState.sil` is the current-`silverc` port fixture for the
validator-owned state machine. It models one validator UTXO and keeps the core
legacy invariants:

- validators stake KAS, never PROM
- minimum stake is `MIN_STAKE_KAS = 10000`
- commit bond is `BOND_PERCENT = 10`
- withdrawal cooldown is `COOLDOWN_BLOCKS = 100800`
- reveal verification uses the same H-001 canonical preimage as
  `ValidatorStakingH001.sil`

The port uses `#[covenant.singleton(mode = transition)]` because current
Silverscript expresses contract state as covenant-authorized UTXO state, not as
legacy global maps. The fixture currently covers:

- `commitVote`
- `revealVote`
- `slashInvalidReveal`
- `requestWithdraw`
- `completeWithdraw`

The shared verifier compiles this fixture against the pinned upstream
Silverscript ref, builds all covenant declaration sigscripts, and runtime-tests
the `commitVote`, `revealVote`, `slashInvalidReveal`, `requestWithdraw`, and
`completeWithdraw` transitions with real Schnorr signatures and authorized
covenant outputs:

```bash
python3 scripts/verify_silverc_h001.py
```

Current runtime coverage:

- `commitVote` accepts a valid 10% bond, validator signature, and successor state
- `commitVote` rejects a bond below 10% of stake
- `commitVote` rejects negative signed block heights
- `revealVote` accepts a valid commitment, validator signature, and successor state
- `revealVote` rejects a salt that does not match the commitment
- `revealVote` rejects negative signed salts
- `slashInvalidReveal` accepts a provably invalid reveal and slashed successor state
- `slashInvalidReveal` rejects slashing when the reveal matches the commitment
- `slashInvalidReveal` rejects negative signed salts
- `requestWithdraw` accepts an active validator with no open commitment
- `requestWithdraw` rejects while a vote commitment is open
- `requestWithdraw` rejects negative signed block heights
- `completeWithdraw` accepts zero-output termination after cooldown
- `completeWithdraw` rejects before the cooldown expires

Current operator coverage is 24 unit/security tests, including a fixed public
interoperability vector for transaction ID, covenant ID, sighash,
signing-request hash, and contextual storage-mass commitment.

Current signed-int deployment boundary:

- upstream Silverc entrypoint numeric arguments are signed `int`
- deployable `salt` and `block_height` values are scoped to `0..=i64::MAX`
- Rust retains raw `u64` H-001 byte vectors, including `u64::MAX`, for
  compatibility testing only
- Rust deployment calls must use `build_silverc_checked` or
  `validate_silverc_commitment_bounds`
- CI proves signed negative Silverc values do not match the Rust `u64::MAX`
  vector, so there is no implicit two's-complement workaround

Remaining deployment blockers:

- real funded testnet-10 operator inputs and external BIP340 signatures
- confirmed `operator_record` receipts plus independent node/explorer evidence
- the external signed metrics-oracle transaction and exact-commit release evidence

## Silverc CLI release bundle smoke

`scripts/smoke_silverc_artifacts.py` compiles every current-Silverc fixture
through the pinned upstream `silverc` binary and validates the resulting JSON
artifact structure:

- non-empty compiled script bytes
- compiler version
- state layout
- expected ABI entrypoints for each Prometheus fixture

Generated artifacts are written to `/tmp/prometheus-silverc-artifacts` by
default and are not committed. Use `--out-dir` to choose another output
directory. Use `--archive /path/to/prometheus-silverc-artifacts.tar.gz` to
produce a deterministic tarball for operator handoff. The script also writes
`manifest.json` with deterministic rollout metadata:

- pinned Silverscript ref and resolved commit
- source SHA-256 for each fixture
- constructor-args SHA-256 for each fixture
- artifact SHA-256
- compiled script SHA-256 and byte length
- state layout and ABI entrypoints

The script validates the manifest after writing it, and repeated local runs
produce the same manifest and archive for the same source tree and pinned
Silverscript ref. CI builds the manifest and checks that the optional archive
contains the manifest. This is a CI-safe release-bundle gate for the available
current-Silverc CLI surface; it does not claim that contracts were deployed to a
network.

## Deploy preflight

`scripts/preflight_silverc_deploy.py` validates an already-built release bundle
from either `--bundle-dir` or `--archive` before any network deploy attempt. It
checks:

- safe archive layout
- manifest schema and expected fixture order
- source, constructor-args, artifact, and compiled-script SHA-256 hashes
- non-empty ABI and state layout metadata
- public operator inputs: network, RPC URL, deployer address, and metrics-oracle
  public key
- whether upstream `silverc` exposes a network deploy command and whether the
  repository Toccata-v1 genesis operator is present

The preflight intentionally does not accept private keys and does not deploy.
Upstream `silverc` still exposes compile/AST artifact generation only, but the
preflight now reports `deploy_supported: true` when the workspace-registered
`prometheus-silverc-deployer` binary is present and all public inputs exist.
This distinguishes the upstream CLI limitation from Prometheus' implemented
network operator.

Use `--runbook-out <path>` to emit a Markdown operator handoff next to the JSON
plan. The runbook is generated only after bundle and public-input validation
passes. It lists the inspected network, missing public inputs, the deploy-tool
capability status, each contract artifact with script SHA-256 and script byte
length, the safe operator sequence, and the remaining deploy blockers. It still
does not include private keys, seed phrases, wallet files, or keystore material.
CI checks that the runbook recognizes the repository operator, remains explicit
that the Python preflight itself does not broadcast, and contains no signing
material.

## Keyless Toccata-v1 genesis operator

`modules/silverc-deployer` implements the network transaction path that upstream
`silverc` does not provide. It uses official pinned `rusty-kaspa` v2.0.1 APIs to
build transaction version 1 with compute budget 10, derive and bind the covenant
ID, calculate and commit contextual storage mass, export the public
`SIG_HASH_ALL` digest, verify an
external BIP340 signature and complete transaction, run a live synced-node and
Toccata-activation preflight, broadcast only after exact signing-request hash
acknowledgement, and observe the deployed covenant UTXO. `testnet-10` is the
pinned supported testnet; `testnet-12` remains unsupported because v2.0.1 has no
parameters for it.

The CLI has no private-key, seed, wallet, keystore, password, or raw transaction
input. Official PSKT/PSKB is not used because its audited input builder creates
legacy sigop-count commitments where Toccata transaction v1 requires an explicit
compute-budget commitment. Contextual storage mass is a separate v1 transaction
commitment and is calculated through the official consensus API.
See [`docs/runbooks/silverc-genesis-operator.md`](../../../docs/runbooks/silverc-genesis-operator.md)
for schemas, commands, safety gates, and rollback handling.

## External deploy requests

`scripts/build_silverc_deploy_requests.py` emits one public deploy-request JSON
file per current-Silverc contract plus a request-set summary and Markdown
runbook for the repository genesis operator and its external signer boundary.
Each request is bound to the validated release-bundle manifest by source,
constructor-args, artifact, and script hashes.

The request builder intentionally does not accept private keys, sign, assemble
chain transactions, broadcast, deploy contracts, or update status files. It also
rejects RPC URLs with embedded credentials. The output status is
`REQUESTS_READY_FOR_KEYLESS_GENESIS_OPERATOR` until the repository keyless
orchestrator consumes the requests and returns real `operator_record` receipts.

`scripts/verify_silverc_deploy_requests.py` independently verifies the request
set before operator handoff. It checks the request-set hash, every per-contract
request hash, manifest-bound source/constructor/artifact/script hashes, fixture
order, constructor args, safety flags, and secret-field rejection.

## Deploy operator procedure

`scripts/build_silverc_deploy_operator_procedure.py` turns a verified public
deploy request set into a deploy-operator checklist and required public result
evidence contract. It reuses the same release-bundle/request-set validation as
the deploy-request verifier, then emits `deploy-operator-procedure.json/.md`
with the request-set hash, per-contract request hashes, external operator
sequence, required `operator_record` result fields, and repository boundary.

The procedure intentionally does not accept private keys, raw transactions,
serialized transactions, signing material, or wallet files. It also does not
assemble, sign, broadcast, deploy contracts, or update status files. The
handoff package includes this procedure for every generated deploy request set,
and the release-readiness audit treats missing or unsafe procedure files as a
failed gate.

## Operator receipt import from external results

`scripts/build_silverc_operator_receipts.py` converts public external
deploy-orchestrator results into canonical `operator_record` receipts. The
input must use `result_type:
prometheus_silverc_external_deploy_results`, must reference the verified
request-set SHA-256, and must contain one confirmed result per contract in
manifest order.

The importer validates the release bundle, re-validates the deploy request set,
checks every result against the verified request hash, rejects secret-like field
names and raw/serialized transaction fields, writes `operator_record` receipts, and then immediately runs the same
receipt verifier used by status staging. It does not accept keys, sign, assemble
chain transactions, broadcast, deploy contracts, or update status files.

`scripts/build_silverc_operator_handoff.py` accepts `--orchestrator-results` to
include this import path in the public handoff package. When real public results
are supplied, the handoff can include `operator-receipts.from-results.json`,
`operator-receipts-import-summary.json`, and `operator-receipts-import.md`; the
handoff remains blocked until real funded deployment receipts, public chain
evidence, and the other release gates are actually proven.

## Deployment receipt verifier

`scripts/verify_silverc_deploy_receipts.py` validates public deployment receipt
records against a previously built current-Silverc release bundle. It accepts
either `--bundle-dir` or `--archive`, checks that every receipt matches the
manifest contract order plus source, constructor-args, artifact, and script
hashes, and emits a JSON summary plus optional Markdown operator runbook.

The verifier intentionally does not accept private keys, sign, broadcast, or
update status files. It also rejects secret-like field names and raw/serialized transaction fields in receipt JSON.
`modules/contracts/silverc/deploy-receipts.sample.json` is a synthetic
`ci_fixture` document used only to keep the schema and negative checks green in
CI. Real deployment status may be recorded only from verified
`operator_record` receipts; use `--require-operator-record` before copying any
contract instance IDs into `memory/STATUS.md`.

## Public receipt-evidence verifier

`scripts/verify_silverc_deploy_receipt_evidence.py` validates a public
node/explorer evidence snapshot against verified `operator_record` deployment
receipts. The evidence must reference the verified receipts SHA-256, the
release-bundle metadata, one confirmed public observation per contract, matching
deploy transaction IDs, matching block hashes, and confirmations greater than
or equal to the receipt confirmations.

The verifier rejects secret-like fields and raw/serialized transaction fields.
It does not query nodes, accept keys, assemble transactions, sign, broadcast,
deploy contracts, or update status files. The operator handoff builder accepts
this evidence via `--deploy-receipt-evidence`; once real operator receipts are
present, missing public receipt evidence remains a handoff blocker.

## Deployment status staging

`scripts/stage_silverc_deployment_status.py` builds a manual deployment-status
draft from verified `operator_record` receipts. It reuses the release-bundle
manifest validation and receipt verifier, rejects `ci_fixture` receipts, and can
emit a JSON status draft plus a Markdown snippet for review.

The script intentionally does not update `memory/STATUS.md`. Operators must
first verify the public deploy transaction IDs and deployed instance IDs against
a trusted node or explorer, then copy only public contract IDs into status files
or release notes.

## Operator handoff package

`scripts/build_silverc_operator_handoff.py` builds a public handoff directory
from an existing release archive. It copies the archive, runs deploy preflight,
builds and verifies the keyless genesis deploy request set, adds the deploy operator
procedure, can import public confirmed operator results into
`operator_record` receipts, verifies the synthetic CI receipt fixture,
optionally verifies real `operator_record` receipts, optionally verifies public
node/explorer receipt evidence for those receipts, validates the
metrics-oracle report, builds the unsigned metrics-oracle transaction request,
can verify a public external-operator capability record, can verify a public
metrics-oracle transaction result, can verify public node/explorer evidence for
that transaction result, can stage a manual metrics-oracle status draft, can
verify public release-hardening evidence for the exact release commit, and emits
`HANDOFF.md` plus `operator-handoff-summary.json`.

The package is intentionally blocked until real network deploy/orchestration
tooling, verified `operator_record` receipts, and signer-ready contract instance
IDs exist. When real receipts are present, missing public receipt evidence is
also a blocker. When a public metrics-oracle transaction result is present,
missing public tx evidence is also a blocker. It does not accept private keys,
sign, broadcast, deploy contracts, raw transactions, or update status files.
Missing public release-hardening evidence is also a blocker before rollout.

## Release-readiness audit

`scripts/audit_silverc_release_readiness.py` validates a generated public
operator handoff directory before any rollout claim. It checks:

- the handoff summary status, blocker list, safety flags, and included-file list
- required handoff files for deploy preflight, deploy requests, receipt checks,
  deploy operator procedure, optional public receipt evidence, metrics report
  preflight, unsigned tx request, optional oracle tx result/status draft, and
  optional release-hardening evidence
- component summary statuses match the handoff summary
- JSON artifacts do not contain secret-like keys or raw/serialized transaction
  fields

The audit emits `ROLLOUT_BLOCKED` while real deploy/orchestration or oracle
operation evidence is missing. `--require-ready` turns that into a failing gate,
which should only pass after real operator receipts, public receipt evidence,
verified oracle tx results, deploy tooling, and public release-hardening
evidence for the exact rollout commit are complete. The audit does not accept
keys, sign, assemble, broadcast, deploy, or update status files.

## GovernanceAutoTuningState.sil

`GovernanceAutoTuningState.sil` is the current-`silverc` port fixture for
weekly protocol parameter tuning. It resolves the deployment-blocking Q-003
stub in the current-Silverc path by making `fp_rate` an explicit signed
metrics-oracle input instead of an implicit `oracle_get_fp_rate() -> 0` value.

The fixture keeps the legacy tuning invariants that are safe to express in the
current covenant state model:

- tuning interval is `TUNING_INTERVAL_BLOCKS = 604800`
- confidence target remains `TARGET_FP_RATE_MAX = 50` (0.5%, 10000x scaled)
- reported `fp_rate` is bounded to `0..10000`
- confidence bounds remain `CONFIDENCE_FLOOR = 5000` and
  `CONFIDENCE_CEILING = 9900`
- stake bounds remain `MIN_STAKE_KAS_FLOOR = 1000` and
  `MIN_STAKE_KAS_CEILING = 100000`
- reward bounds remain `REWARD_FLOOR = 10` and `REWARD_CEILING = 1000`

The fixture intentionally does not pretend to support legacy global state,
string parameter lookup, cross-contract `call(...)`, or an off-chain oracle
operator implementation. The deploy path must still provision and operate the
metrics signer represented by `metrics_oracle_pk`.

The shared verifier currently compiles this fixture against the same pinned
upstream Silverscript ref and runtime-tests covenant transitions for:

- `reportMetrics`
- `autoTune`

Verified rejection paths include `fp_rate` above `MAX_FP_RATE` and auto-tuning
before `TUNING_INTERVAL_BLOCKS`.

## Metrics-oracle report preflight

`scripts/preflight_metrics_oracle_report.py` validates the public metrics report
that an operator will use for `GovernanceAutoTuningState.reportMetrics`.
It does not sign, hold keys, or broadcast. The real covenant signature remains a
transaction-input signature produced by the metrics-oracle wallet outside this
repository.

The report schema is demonstrated in
`metrics-oracle-report.sample.json`. The preflight validates:

- `schema_version = 1`, `contract = GovernanceAutoTuningState`, and
  `entrypoint = reportMetrics`
- `metrics_oracle_pubkey` as a 32-byte public key hex string
- nonnegative `active_validators`, `active_guardians`, and `proposals_per_day`
- `fp_rate` in the contract-compatible range `0..10000`
- monotonic `block_height >= previous_state.last_metrics_block`
- absence of secret-like fields such as private keys, seeds, wallet data, or
  keystore material

It emits a JSON preflight plan with the exact public `reportMetrics` argument
mapping and can emit a Markdown operator runbook. CI checks the sample report,
the generated plan/runbook, and a negative secret-field rejection case.

## Metrics-oracle unsigned transaction request

`scripts/build_metrics_oracle_tx_request.py` binds a validated public metrics
report to the validated current-Silverc release bundle and the
`GovernanceAutoTuningState` artifact metadata. It emits a deterministic,
unsigned operator request for the external deploy/transaction assembler.

The request includes:

- the release bundle Silverscript ref/commit and GovernanceAutoTuning source,
  constructor-args, artifact, and script hashes
- the `__covenant_entrypoint_auth_reportMetrics` ABI binding
- the exact public `reportMetrics` arguments
- the metrics-oracle public key and external `oracle_sig` requirement
- a request SHA-256 for operator handoff/review
- safety flags proving the script does not accept private keys, sign, assemble
  a chain transaction, or broadcast

Without `--contract-instance-id`, the request status remains
`BLOCKED_UNTIL_CONTRACT_INSTANCE_ID`. With a public deployed contract instance
ID or outpoint, the status becomes `READY_FOR_EXTERNAL_TX_ASSEMBLER`; signing
and broadcast still remain outside this repository. CI checks both states and a
negative `--require-contract-instance-id` failure path.

## Metrics-oracle operator procedure

`scripts/build_metrics_oracle_operator_procedure.py` turns a signer-ready
metrics-oracle tx request into a public external-operator checklist. It
re-validates the request against the release bundle and emits:

- the request hash, contract instance binding, artifact hash, and script hash
- the public result fields required by `verify_metrics_oracle_tx_result.py`
- the external sequence for assembler mapping, wallet signature, broadcast,
  confirmation, and operator-record evidence
- safety flags proving the repository does not accept keys, raw transactions,
  signing material, transaction assembly, broadcast, deploy, or status writes

The handoff package includes `metrics-oracle-operator-procedure.json/.md`
whenever the tx request is signer-ready. This reduces the oracle-operations
blocker to an explicit external wallet/orchestrator execution step while keeping
all sensitive material outside the repository.

## External operator capability verification

`scripts/verify_external_operator_capability.py` validates a public
external-operator capability record against the generated deploy operator
procedure and, when available, the metrics-oracle operator procedure. It checks:

- `schema_version = 1`, `kind = prometheus.external_operator.public_capability`,
  and `status = PUBLIC_CAPABILITY_ATTESTED`
- network, deploy request-set hash, deploy request count, and public deploy
  result type match the deploy operator procedure
- the external operator attests transaction version 1,
  `kaspa_txscript::pay_to_script_hash_script` over the compiled contract script,
  official `kaspa_consensus_core::hashing::covenant_id` derivation from the
  funding outpoint and unbound genesis outputs, and funding-input binding only
  after the covenant ID is derived
- metrics tx-request hash, contract instance id, and public oracle result type
  match the metrics-oracle operator procedure when supplied
- repository-boundary flags state public artifacts, operator records, external
  chain payloads, and manual status updates only
- safety flags prove the verifier does not accept keys, raw transactions, sign,
  assemble, broadcast, deploy, or update status files
- JSON inputs reject secret-like field names and raw/serialized transaction
  fields

`scripts/build_silverc_operator_handoff.py --operator-capability <file>` copies
the public capability record into the handoff directory, writes
`external-operator-capability-summary.json/.md`, and exposes
`external_operator_capability_status` in `operator-handoff-summary.json`.
`scripts/audit_silverc_release_readiness.py` validates those files whenever the
status is `EXTERNAL_OPERATOR_CAPABILITY_VERIFIED`. This makes the external tool
boundary auditable without putting keys, raw transactions, or deployment actions
inside the repository.

## Metrics-oracle transaction result verifier

`scripts/verify_metrics_oracle_tx_result.py` validates a public record of an
external `GovernanceAutoTuningState.reportMetrics` transaction after an
operator has assembled, signed, broadcast, and confirmed it outside this
repository.

The verifier requires the signer-ready unsigned tx request plus the release
bundle. It checks:

- `result_type = prometheus.metrics_oracle.report_metrics.tx_result`
- `status = confirmed` and `provenance.type = operator_record`
- matching network, request SHA-256, contract name, entrypoint, and instance ID
- matching metrics payload hash and entrypoint argument hash
- public transaction evidence: tx id, block hash, confirmations, DAA score, and
  UTC broadcast/confirmation timestamps
- absence of private keys, seeds, wallet data, keystore material, and raw or
  serialized transaction payloads

It emits `METRICS_ORACLE_TX_RESULT_VERIFIED` plus a Markdown runbook for
operator review. It does not accept keys, sign, assemble, broadcast, deploy, or
update status files. CI covers a positive public result plus blocked request,
secret-field, raw-transaction, and request-hash tamper rejection paths.

## Metrics-oracle public tx evidence

`scripts/verify_metrics_oracle_tx_evidence.py` binds a verified public
metrics-oracle transaction result to a public node/explorer snapshot. It checks
the release bundle, tx-request hash, tx-result hash, contract instance, payload
hashes, tx id, block hash, DAA score, and confirmations while rejecting
secret-like fields and raw or serialized transaction payloads.

When `--metrics-tx-result` is supplied to the operator handoff builder, public
tx evidence must be supplied with `--metrics-tx-evidence` before handoff
readiness can pass. The verifier does not query nodes, accept keys, sign,
assemble, broadcast, deploy, or update status files.

## Metrics-oracle status staging

`scripts/stage_metrics_oracle_status.py` builds a manual metrics-oracle
status-update draft from a signer-ready unsigned request and verified public
transaction result. It reuses the same release-bundle, request, and tx-result
validation as the verifier, then emits `metrics-oracle-status-draft.json/.md`
for operator review.

The stage intentionally does not update `memory/STATUS.md` or any release
status file. It rejects blocked tx requests, secret-like fields, raw or
serialized transaction payloads, and only records public evidence such as tx id,
block hash, confirmations, DAA score, contract instance ID, and payload hashes.
When `--metrics-tx-result` is supplied, the handoff package includes the status
draft and the release-readiness audit treats missing or unsafe draft files as a
failed gate.

## Release-hardening evidence

`scripts/verify_release_hardening_evidence.py` validates a public
release-hardening evidence document for the exact release commit. The evidence
must bind the repository, protected branch, successful `Prometheus CI`,
`Security Audit`, and `pages-build-deployment` checks, branch controls,
rollback documentation, public Pages verification, and release-note
requirements.

The verifier rejects secret-like fields and raw or serialized transaction
payloads. It does not query GitHub, accept credentials, change repository
settings, deploy contracts, assemble transactions, sign, broadcast, or update
status files. `scripts/build_silverc_operator_handoff.py` accepts this evidence
via `--release-hardening-evidence`; missing evidence remains a handoff blocker
until the final rollout commit has a verified public snapshot.

## DevIncentivePoolState.sil

`DevIncentivePoolState.sil` is the current-`silverc` port fixture for the
developer grant state machine. It models one active grant UTXO slot and PROM
pool accounting.

The fixture keeps the legacy grant invariants that are safe to express in the
current covenant state model:

- maximum grant is `MAX_GRANT_PROM = 100000`
- grant voting period is `GRANT_VOTING_BLOCKS = 604800`
- reward formula uses `REWARD_PER_LINE = 10`
- complexity is bounded by `MIN_COMPLEXITY = 1` and `MAX_COMPLEXITY = 10`
- execution quorum is `QUORUM_VOTES = 10`
- validator approval threshold is `VALIDATOR_QUORUM = 6700`
- pool accounting remains PROM-denominated, but PROM is not a staking asset

The fixture intentionally does not pretend to support legacy global maps,
string storage, `msg.sender`, event emission, cross-contract validator lookups,
emission-contract deposits, or direct PROM `transfer(...)` in current Silverc.
The known legacy `deposit()` ACL question remains a deployment/orchestration
decision once the emission authority is finalized.

The shared verifier currently compiles this fixture against the same pinned
upstream Silverscript ref and runtime-tests covenant transitions for:

- `proposeGrant`
- `voteGrant`
- `executeGrant`

Verified rejection paths include grant amount above `MAX_GRANT_PROM`, voting at
`voting_end_block`, execution below `QUORUM_VOTES`, and execution below
`VALIDATOR_QUORUM`.

## CommunityDonationsState.sil

`CommunityDonationsState.sil` is the current-`silverc` port fixture for the
community donation pool state machine. It models donation accounting and one
active disbursement proposal/rule UTXO slot.

The fixture keeps the legacy invariants that are safe to express in the current
covenant state model:

- minimum donation is `MIN_DONATION_KAS = 1`
- disbursement quorum is `DISBURSEMENT_QUORUM = 10`
- validator approval threshold is `VALIDATOR_QUORUM = 6700`
- pool accounting remains KAS-denominated
- disbursements require governance signature at execution

The fixture intentionally does not pretend to support legacy global maps,
string storage, `msg.sender`, `tx.value`, event emission, cross-contract
validator lookups, or direct KAS `transfer(...)` in current Silverc. Those
concerns remain deployment/orchestration work around the covenant state model.

The shared verifier currently compiles this fixture against the same pinned
upstream Silverscript ref and runtime-tests covenant transitions for:

- `donateKas`
- `proposeDisbursement`
- `voteDisbursement`
- `executeDisbursement`

Verified rejection paths include zero donation amount, disbursement amount
above pool balance, voting at `voting_end_block`, and execution below
`DISBURSEMENT_QUORUM`.

## RuleStorageState.sil

`RuleStorageState.sil` is the current-`silverc` port fixture for the rule
proposal and storage state machine. It models one active proposal/rule UTXO
slot and keeps the deployment-critical legacy invariants:

- rule content uses CIDv1 binary as `byte[36]`
- minimum AI confidence is `MIN_CONFIDENCE = 8500`
- validator quorum is `VALIDATOR_QUORUM = 6700`
- voting duration is `VOTING_BLOCKS = 864000`
- accepted/rejected proposal outcomes are represented as explicit Guardian
  reputation events for orchestration with `GuardianReputationState.sil`

The fixture intentionally does not pretend to support legacy global maps,
`msg.sender`, cross-contract `call(...)`, event emission, or KRC20 minting in
current Silverc. Those concerns remain deployment/orchestration work around the
current covenant state model.

The shared verifier compiles this fixture against the same pinned upstream
Silverscript ref, builds covenant declaration sigscripts, and runtime-tests
the proposal lifecycle transitions for:

- `submitProposal`
- `voteOnProposal`
- `finalizeProposal`
- `deactivateRule`

Current runtime coverage:

- `submitProposal` accepts a valid guardian signature and successor state
- `submitProposal` rejects confidence below `MIN_CONFIDENCE`
- `voteOnProposal` accepts a valid validator support vote and successor state
- `voteOnProposal` rejects votes at or after `voting_end_block`
- `finalizeProposal` accepts accepted and rejected proposal outcomes
- `finalizeProposal` rejects zero-vote finalization
- `deactivateRule` accepts deactivation of an active accepted rule
- `deactivateRule` rejects pending/non-accepted rule state

## GuardianReputationState.sil

`GuardianReputationState.sil` is the current-`silverc` port fixture for the
guardian-owned reputation state machine. Guardian reputation remains canonical
on Kaspa L1 and does not introduce badge, NFT, Kasplex, or staking semantics.

The fixture models one guardian reputation UTXO and keeps these legacy
invariants:

- no Guardian staking
- starting reputation is `REPUTATION_START = 1000`
- minimum voting reputation is `MIN_REPUTATION = 1000`
- maximum reputation is `REPUTATION_MAX = 100000`
- minimum compute is `MIN_COMPUTE_GFLOPS = 100`
- model type `0` is LLaMA-3-70B and model type `1` is LLaMA-3-8B

The shared verifier compiles this fixture against the same pinned upstream
Silverscript ref and builds covenant declaration sigscripts for:

- `register`
- `proposalAccepted`
- `proposalRejected`

Current runtime coverage:

- `register` accepts a valid guardian signature and state transition
- `register` rejects compute power below `MIN_COMPUTE_GFLOPS`
- `proposalAccepted` accepts a valid governance signature and state transition
- `proposalAccepted` computes `isqrt(compute_power_gflops) * 100` on-chain
- `proposalRejected` accepts a valid governance signature and state transition
- `proposalRejected` rejects unregistered guardian state

Current scope note:

- current upstream Silverc uses bounded `for` loops rather than `while`
- the legacy `sqrt(compute_power) * 100` accepted-proposal increment is
  implemented as exact integer square root for the allowed `< 1_000_000`
  compute-power range
- `proposalAccepted` caps reputation at `REPUTATION_MAX`
