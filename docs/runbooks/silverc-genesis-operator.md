# SilverScript Genesis Operator Runbook

Status: implementation complete; real testnet evidence still required.

## Purpose

`prometheus-silverc-deployer` assembles the official Kaspa Toccata transaction-v1
covenant-genesis transaction, exports only its 32-byte Schnorr sighash, verifies
an external BIP340 signature, submits the fully verified transaction, and
observes the resulting covenant UTXO. It never accepts or stores a private key,
seed phrase, wallet, keystore, password, or raw serialized transaction artifact.

The operator uses the repository-pinned `rusty-kaspa` v2.0.1 APIs. Its immutable
genesis profile is:

- transaction version: `1`
- storage mass commitment: contextual `storage_mass` (not max overall mass)
- funding-input compute budget: `10`
- signature hash type: `SIG_HASH_ALL`
- contract output index: `0`
- authorizing input index: `0`
- contract script: official `pay_to_script_hash_script(compiled_script)`
- covenant ID: official funding-outpoint plus unbound contract-output derivation
- covenant binding: applied only after covenant-ID derivation

## Supported Networks

The pinned consensus profiles support `mainnet`, `testnet-10`, and `devnet` for
this operator. `testnet-12` is rejected because v2.0.1 has no parameters for it.
`simnet` is rejected because Toccata is configured as never active there.

The pinned activation DAA scores are `474165565` on mainnet and `467579632` on
testnet-10. Calendar dates alone are not accepted as proof. `preflight` and
`broadcast` query a synced UTXO-indexed node and require the expected network,
a live DAA score at or above the network's Toccata activation, and exact live
funding UTXO state. `broadcast` repeats this exact funding validation.

The exact target `kaspa-resolver://public` selects the public resolver bundled
with pinned `rusty-kaspa`. This mode enforces TLS and is restricted to
`testnet-10`; resolver lookalikes, credentials, query strings, fragments,
HTTP(S) URLs, other testnet suffixes, and mainnet resolver use fail closed.
Direct `ws://` and `wss://` node URLs remain supported. Public resolver nodes
are best-effort infrastructure and do not replace independent chain evidence.

## Select The Deployment Profile

The Python handoff layer accepts exactly two release-manifest-bound profiles:

- `full`: all seven current-Silverc fixtures; requires the public
  metrics-oracle x-only key and remains the only path that can eventually pass
  the full operator-handoff/readiness audit.
- `testnet-10-validator-staking-h001`: only `ValidatorStakingH001`; requires
  `--network testnet` and the exact `kaspa-resolver://public` target; forbids and
  omits `--metrics-oracle-pubkey`.

The H-001 profile is stricter than the Rust operator's general direct-node
capability. Its receipt, evidence, and status values remain canary-specific and
must never be copied into full-release, production, or metrics-oracle status.
Changing the profile object, contract selection, or release-manifest binding
invalidates the request hash and is rejected after rehashing as well.

Prepare and verify the canary handoff only after building the deterministic
release archive:

```bash
python3 scripts/preflight_silverc_deploy.py \
  --archive /tmp/prometheus-silverc-artifacts.tar.gz \
  --deployment-profile testnet-10-validator-staking-h001 \
  --network testnet \
  --rpc-url kaspa-resolver://public \
  --deployer-address <public-deployer-address> \
  --plan-out /tmp/prometheus-h001-canary-preflight.json

python3 scripts/build_silverc_deploy_requests.py \
  --archive /tmp/prometheus-silverc-artifacts.tar.gz \
  --deployment-profile testnet-10-validator-staking-h001 \
  --out-dir /tmp/prometheus-h001-canary-requests \
  --network testnet \
  --rpc-url kaspa-resolver://public \
  --deployer-address <public-deployer-address> \
  --request-set-out /tmp/prometheus-h001-canary-request-set.json

python3 scripts/verify_silverc_deploy_requests.py \
  --archive /tmp/prometheus-silverc-artifacts.tar.gz \
  --request-set /tmp/prometheus-h001-canary-request-set.json \
  --requests-dir /tmp/prometheus-h001-canary-requests \
  --summary-out /tmp/prometheus-h001-canary-verification.json
```

Expected canary scope: one request file named
`01-ValidatorStakingH001.deploy-request.json`, no metrics-oracle key, and
`CANARY_DEPLOY_REQUEST_VERIFIED`. A successful real transaction remains one
canary observation, not a full rollout claim.

## Build

```bash
cargo build --release -p prometheus-silverc-deployer
```

Use the release binary at
`target/release/prometheus-silverc-deployer`. Generate the verified deploy
request and deterministic Silverc artifact bundle with the existing scripts in
`modules/contracts/silverc/README.md` before continuing.

## Funding-Free Node Probe

Before preparing any funding, verify live testnet-10 connectivity, sync state,
UTXO-index availability, and Toccata activation through the official resolver:

```bash
target/release/prometheus-silverc-deployer probe \
  --rpc-url kaspa-resolver://public \
  --network-id testnet-10 \
  --evidence-out /path/to/testnet-10.node-probe.json
```

The public evidence records both the resolver target and the resolved TLS wRPC
endpoint. This read-only probe does not inspect a funding outpoint and is not
permission to sign or broadcast. The funding-bound `preflight` and the second
live UTXO validation immediately before broadcast remain mandatory.

## Public Funding Input

Create the funding specification outside the repository. It contains public
chain data only and must match one deploy request and the deployer's Schnorr P2PK
address. Both minimum and maximum fee bounds are mandatory.

```json
{
  "schema_version": 1,
  "kind": "prometheus.silverc.genesis_funding",
  "network_id": "testnet-10",
  "request_sha256": "<64 lowercase hex characters>",
  "contract_name": "<request contract name>",
  "funding_outpoint": {
    "transaction_id": "<64 lowercase hex characters>",
    "index": 0
  },
  "funding_utxo": {
    "amount": 100000,
    "script_public_key": {
      "version": 0,
      "script_hex": "<public funding script hex>"
    },
    "block_daa_score": 467579700,
    "is_coinbase": false
  },
  "genesis_output_value": 80000,
  "minimum_fee_sompi": 1000,
  "maximum_fee_sompi": 3000,
  "change_output": {
    "value": 18000,
    "script_public_key": {
      "version": 0,
      "script_hex": "<same deployer P2PK script hex>"
    }
  }
}
```

Replace `block_daa_score` with the exact live DAA score of the selected funding
UTXO. The funding and change scripts must both resolve to the deployer address
from the deploy request. Covenant-bound funding UTXOs, coinbase UTXOs, zero-value
outputs, arithmetic overflow, fees outside the approved range, exact funding
outpoint mismatch, credentialed RPC URLs, and unsupported network profiles fail
closed.

The signing request binds and validates all funding context returned by the live
node, including `block_daa_score`, `is_coinbase = false`, and both
`minimum_fee_sompi` / `maximum_fee_sompi`.

## Operator Flow

Set paths to one verified deploy request, its exact artifact JSON, and the
public funding specification:

```bash
OP=target/release/prometheus-silverc-deployer
REQUEST=/path/to/01-Contract.deploy-request.json
ARTIFACT=/path/to/Contract.json
FUNDING=/path/to/Contract.genesis-funding.json
```

1. Verify the node and live Toccata state:

```bash
"$OP" preflight \
  --request "$REQUEST" \
  --funding "$FUNDING" \
  --evidence-out /path/to/Contract.node-preflight.json
```

2. Build the deterministic transaction and public signing request:

```bash
"$OP" prepare \
  --request "$REQUEST" \
  --artifact "$ARTIFACT" \
  --funding "$FUNDING" \
  --signing-request-out /path/to/Contract.signing-request.json
```

3. Send only `sighash_hex` and the expected public-key identity from the signing
request to the approved external vault or HSM. The signer returns public JSON:

```json
{
  "schema_version": 1,
  "kind": "prometheus.silverc.genesis.signature_response",
  "status": "SIGNED_BY_EXTERNAL_OPERATOR",
  "request_sha256": "<copied from signing request>",
  "signing_request_sha256": "<copied from signing request>",
  "contract_name": "<copied from signing request>",
  "transaction_id": "<unsigned_transaction_id from signing request>",
  "input_index": 0,
  "sighash_type": "SIG_HASH_ALL",
  "sighash_hex": "<32-byte digest as 64 hex characters>",
  "xonly_public_key_hex": "<expected 32-byte public key>",
  "schnorr_signature_hex": "<64-byte BIP340 signature>"
}
```

4. Rebuild everything from source inputs and verify both signature and complete
Kaspa transaction:

```bash
"$OP" verify-signature \
  --request "$REQUEST" \
  --artifact "$ARTIFACT" \
  --funding "$FUNDING" \
  --signing-request /path/to/Contract.signing-request.json \
  --signature-response /path/to/Contract.signature-response.json \
  --verification-out /path/to/Contract.signature-verification.json
```

5. After reviewing every public field, explicitly acknowledge the exact
`signing_request_sha256` and submit:

```bash
"$OP" broadcast \
  --request "$REQUEST" \
  --artifact "$ARTIFACT" \
  --funding "$FUNDING" \
  --signing-request /path/to/Contract.signing-request.json \
  --signature-response /path/to/Contract.signature-response.json \
  --acknowledge-signing-request-sha256 '<reviewed hash>' \
  --result-out /path/to/Contract.broadcast-result.json
```

Before any RPC submission, the operator atomically writes
`Contract.broadcast-result.json.intent.json` with the verified transaction ID
and acknowledgement. An OS-managed `Contract.broadcast-result.json.lock`
prevents concurrent processes and is released automatically on exit or crash. A
retry validates the journal and reconciles the known transaction ID against the
covenant UTXO and mempool before it can submit. The journal is finalized before
the public result file is written, so an interruption cannot trigger a blind
resubmission. Once a submission attempt has started, a later run may only
reconcile; if the node cannot yet prove mempool or covenant-UTXO presence, the
operator fails closed and requires later/public evidence instead of sending
again.

6. Rebuild and verify the complete signed transaction again, then observe its
exact contract output on the synced indexed node:

```bash
"$OP" observe \
  --request "$REQUEST" \
  --artifact "$ARTIFACT" \
  --funding "$FUNDING" \
  --signing-request /path/to/Contract.signing-request.json \
  --signature-response /path/to/Contract.signature-response.json \
  --evidence-out /path/to/Contract.node-observation.json
```

The observation first verifies the source-bound BIP340-signed transaction, then
checks outpoint, amount, covenant ID, contract script, and DAA depth. The
existing public receipt-evidence flow still requires independent explorer/block
evidence before rollout status can become ready.

The local suite contains 32 unit/security tests. It includes fixed public
transaction ID, covenant ID, sighash, signing-request hash, and storage-mass
values, resolver fail-closed coverage, plus a file-based
deploy-request/artifact/signing-response roundtrip and closed H-001 canary
profile/tamper guards.

## PSKT Compatibility Note

Do not route these transaction-v1 deployments through the current official
PSKT/PSKB implementation. In both pinned v2.0.1 and the audited upstream state,
its input builder creates legacy sigop-count commitments where Toccata
transaction v1 requires an explicit compute-budget commitment. Contextual
storage mass is a separate v1 transaction commitment. The repository operator
uses the official v1 transaction, sighash, covenant, mass, and
signature-verification APIs directly and fails closed until upstream PSKT/PSKB
adds a compatible v1 input path.

## Rollback

Before broadcast, rollback means discarding the public request/response files;
no on-chain state has changed. After broadcast, a covenant genesis transaction
is immutable. Stop the remaining deployment sequence, preserve public evidence,
open an incident issue, and do not update deployment status until the transaction
and resulting UTXO have been independently reconciled.
