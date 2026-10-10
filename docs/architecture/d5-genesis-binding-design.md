# D5 Genesis / Instance Binding — Design Record (proposal)

Status: **proposed** (Claude, 2026-10-01, brief `bundle-v2-d5-genesis-binding-design`;
Codex review 2026-10-01: working basis, evidence wording corrected in
`bundle-v2-d5-offline-covenant-id`). Decisions: deployment-specific
constructor/compiled identity reviewed separately from the placeholder
fixtures; per-contract authority keys as the draft default (not production key
approval); D5 is off-chain binding now; H-001 is not a D5 anchor.
Binding only after Codex review. No contract logic, Rust, pin, evidence or
runtime acceptance change. v2 stays non-promotable; D1–D7 stay proposed.
Architecture node: MAP M1/MS-B — reviewed deployment manifest → genesis covenant
identity → off-chain state acceptance.

## 1. Traced facts (existing call sites)

| Topic | Fact | Source |
|---|---|---|
| Derivation | `covenant_id = H(funding outpoint txid, index, n, [output index, value, script version, script bytes])`; the binding itself and signatures are excluded | rusty-kaspa v2.0.1 `consensus/core/src/hashing/covenant_id.rs:16-29` |
| Consensus | genesis covenant id is recomputed; mismatch fails with `WrongGenesisCovenantId` | `crypto/txscript/src/covenants.rs:148-160` |
| Deployer | `prepare_genesis` computes the id locally from the funding outpoint and the unbound contract output (index 0, genesis value, P2SH of the artifact script) before signing | `modules/silverc-deployer/src/lib.rs:1010`, `:1075-1091` |
| Txid | Kaspa v1 txid excludes signature scripts, so `deploy_tx_id` and `deployed_instance_id = deploy_tx_id:0` are also fixed before signing | `tx.rs:207-250`; `lib.rs:1133`, `:1178` |
| Post-broadcast | node UTXO must match outpoint, amount, covenant id and script | `lib.rs:1595-1615` (`deployed_contract_entry`) |
| Client | rule observation accepts the covenant id named in an owner-signed manifest; no role registry or genesis allowlist | `modules/client/src/blockchain/rule_observation.rs:471-509` |
| Oracle operator | covenant id comes from the operator-supplied transition spec | `modules/silverc-deployer/src/oracle.rs:743`, `:982` |
| Python tooling | metrics tools identify the contract by outpoint only; receipt/evidence verifiers never read a covenant id or funding outpoint | `scripts/verify_silverc_deploy_receipt_evidence.py:172-174`, `scripts/build_metrics_oracle_tx_request.py:71-113` |
| Guardian / validator node | no covenant or GuardianReputation reader | — |
| Contracts | no constructor takes another contract's covenant id or script hash; `OpInputCovenantId` is used only for self-binding of attestations | `RuleStorageState.sil:103-111`, `:173-186`; pools likewise |
| H-001 evidence | covenant id appears only in the canary summary with a recorded boolean `covenant_id_match`; the funding outpoint is not part of the frozen record, so this record lacks the D5 reconstruction anchor (an external reconstruction from chain data is not ruled out) | `docs/evidence/gh-9-h001-canary-confirmed-2026-08-12.json:30`, `:57` |

## 2. Precomputable vs. evidence-bound identity

| Field | Plan identity (pre-deployment) | Deployment identity (post-confirmation) |
|---|---|---|
| network, bundle id, bundle manifest hash | fixed by the reviewed plan; manifest hash checked against the hardcoded registry pin | same |
| role, contract name, script/constructor-args SHA-256 | fixed by the plan, checked against the validated release manifest | same |
| authority key (validator / governance / metrics-oracle) | declared once, must equal the constructor argument of that contract | same |
| funding outpoint, genesis value | chosen in the plan | the genesis tx must spend it (enforced by consensus through the id) |
| covenant id | **precomputable** from funding outpoint + value + script (existing Rust helper) | must equal the id on the public UTXO |
| deploy tx id / instance id | precomputable only once the full unsigned tx (fees, change) is fixed; not part of the plan | from public evidence |
| block hash, DAA score, confirmations | not available | **public evidence only** |

A claimed id, a fixture, or an operator receipt never proves chain identity.
Recomputation of the id from reviewed plan fields establishes what the id
must be. A stored raw RPC/explorer response together with its own SHA-256
establishes only internal consistency (the claimed fields match the stored
bytes), not provenance or consensus truth: whoever stores the response could
have fabricated it. Accepting chain evidence therefore needs an explicit
trusted-source model, for example responses from at least two independently
operated nodes or explorers, captured by a reviewer who is not the operator,
optionally with a block-hash/DAA cross-check against a header source. Evidence
acceptance stays **blocked** until that model is decided in its own block.
Because the id commits to the script and the constructor arguments, a
lookalike covenant with forged initial state (audit PRM-25) has a different id
unless the hash is broken.

## 3. Circular constructor dependencies

The id hashes the script, and the script embeds the constructor arguments. If
contract A embedded B's id and B embedded A's id, each id would be an input to
the other's hash. Satisfying both would require finding a fixed point of the
hash function; this is not proven impossible but is computationally
infeasible in practice. Cycles are therefore prohibited by policy. Rules:

1. Trust edges (`trusted_roles`: covenant ids embedded as constructor arguments)
   must form a DAG; self-edges are forbidden.
2. Deployment order must be topological, so every embedded id is precomputed
   from an earlier entry. Ids remain precomputable before any signature.
3. The current v2 draft has **no** trust edges. No v2 contract can use another
   contract's id today: there are no runtime cross-contract calls and no
   co-spend (`OpInputCovenantId` of another input) checks.

Recommendation: amend D5. The off-chain binding below is sufficient now.
Constructor-embedded ids are added only together with a concrete co-spend
check, and the validator then enforces rules 1–2.

## 4. Draft binding document (`prometheus.silverc.genesis-binding`, `1-draft`)

```json
{
  "plan": {
    "schema": "prometheus.silverc.genesis-binding", "schema_version": "1-draft",
    "network_id": "testnet-10",
    "release": {"bundle_id": "...", "bundle_manifest_sha256": "...", "silverscript_commit": "..."},
    "authority_keys": {"<name>": {"kind": "governance|metrics_oracle|validator", "xonly_pubkey": "<hex32>"}},
    "contracts": [{"role": "...", "contract_name": "...", "script_sha256": "...",
                   "constructor_args_sha256": "...", "authority_key": "<name>",
                   "genesis_value_sompi": 1, "funding_outpoint": "<txid>:<index>",
                   "trusted_roles": [], "predicted_covenant_id": "<hex32>"}],
    "deployment_order": ["..."]
  },
  "evidence": {"<role>": "<prometheus.silverc.d5.genesis_evidence_candidate v1, section 9>"}
}
```

- The plan hash is the canonical JSON SHA-256 (sorted keys, compact). It is
  pinned out of band by review; the document carries no self-declared hash.
- Roles form a closed table of the six state contracts, each with a key kind
  and constructor position (validated against the `.sil` headers in tests).
  `ValidatorStakingH001` is the frozen canary and not a v2 role.
- `evidence` is absent in the plan phase. Since `bundle-v2-d5-binding-alignment`
  each evidence item is a Rust D5 evidence candidate (section 9). The earlier
  ad-hoc evidence format with a raw response, confirmations and block hash was
  removed.

## 5. Validation order (deterministic, fail-closed)

1. Document shape (`plan`, optional `evidence`; exact field sets everywhere).
2. Plan hash equals the reviewed pin.
3. Schema/version; network in the allowed set (draft: `testnet-10`).
4. Release: bundle id equals the selected bundle; manifest hash equals the hardcoded registry pin.
5. Authority keys: format; every key used.
6. Roles: closed set, each exactly once; contract name per role; script and
   constructor-args hash equal the validated release manifest; authority key
   kind per role; key equals the constructor argument.
7. Anchors: funding outpoint format (uint32 index), unique; genesis value > 0;
   predicted ids well-formed and unique.
8. Trust graph acyclic; deployment order topological.
9. Plan phase result: never executable; always blocked on id recomputation;
   v2 additionally blocked as non-promotable.
10. Evidence phase (draft checks only; acceptance blocked until the
    trusted-source model in section 2 is decided): refused for non-promotable
    bundles. Each role's candidate is checked in two steps.
    - Internal consistency (`verify_candidate_document`):
      - exact field sets;
      - schema, status, classification, trust model, sources and the
        relationship list pinned to the Rust constants via a cross-language
        fixture;
      - fixed output index 0;
      - observed outpoint = expected deploy txid:0; the deploy tx differs from
        the funding tx;
      - observed value, script and covenant id match;
      - not coinbase;
      - DAA chronology and depth;
      - snapshot and candidate hashes.
    - Plan context: the network, contract of the role, funding outpoint and
      genesis value must equal the plan entry, and the calculated covenant id
      must equal the predicted id.

    Covenant ids must be unique. Missing roles → blocked.
11. Acceptance (`accept_state`): **closed gate.** The draft unconditionally
    refuses with `NOT_CONFIRMED`. Any result, whether genuine, forged or
    caller-modified (status, `independently_confirmed`, `executable` or
    blockers), is refused. There is no prepared activation switch. Acceptance
    needs a separately reviewed and explicitly authorized trusted-source and
    recomputation implementation. Role, network and lookalike substitutions are
    rejected earlier, at the candidate-to-plan binding (step 10).

Statuses: `D5_PLAN_CONSISTENT_NOT_EXECUTABLE`,
`D5_PLAN_CONSISTENT_COVENANT_ID_RECOMPUTE_BLOCKED`,
`D5_BLOCKED_MISSING_GENESIS_EVIDENCE`,
`D5_EVIDENCE_CONSISTENT_COVENANT_ID_RECOMPUTE_BLOCKED`. No status claims a
confirmed deployment while the recomputation is unimplemented.

## 6. Validation matrix

Implemented in `scripts/silverc_genesis_binding_draft.py` (no CLI, no writes)
and tested in `scripts/test_silverc_genesis_binding_draft.py`. The sample
`modules/contracts/silverc/genesis-binding.draft.sample.json` uses synthetic
labels, not chain data.

| Case | Code |
|---|---|
| plan altered after review | `PLAN_PIN` |
| lookalike contract (changed constructor args / script) | `COMPILED_IDENTITY` |
| cross-bundle id or manifest hash | `BUNDLE` |
| cross-network plan / evidence / state | `NETWORK`, `EVIDENCE_NETWORK` |
| role ↔ contract substitution, swapped roles | `ROLE_CONTRACT` |
| duplicate / missing / unknown role | `DUPLICATE_ROLE`, `ROLE_SET`, `ROLE_UNKNOWN` |
| wrong key kind, key not the constructor argument, unused key | `KEY_KIND`, `KEY_CONSTRUCTOR`, `KEY_UNUSED` |
| duplicate funding outpoint / covenant id | `DUPLICATE_OUTPOINT`, `DUPLICATE_COVENANT_ID` |
| malformed outpoint, value | `OUTPOINT`, `GENESIS_VALUE` |
| self, two- and three-contract cycles | `CIRCULAR_DEPENDENCY` |
| acyclic edge deployed in the wrong order, unknown edge | `DEPLOYMENT_ORDER`, `TRUST_GRAPH` |
| self-declared hash or extra field | `SHAPE` |
| v2 with evidence | `NON_PROMOTABLE` |
| candidate status / classification / relationship change | `CANDIDATE_SCHEMA` |
| trust model upgraded (independent confirmation, fewer missing checks) | `CANDIDATE_TRUST` |
| relabeled field source | `CANDIDATE_SOURCE` |
| unknown, missing or legacy field (e.g. `raw_response`, `rpc_url`) | `SHAPE` |
| snapshot or candidate hash mismatch | `EVIDENCE_HASH` |
| observed value / script / DAA depth inconsistent | `EVIDENCE_INCONSISTENT` |
| wrong or non-fixed index, coinbase, future DAA, deploy tx = funding tx | `EVIDENCE_ANCHOR` |
| self-consistent candidate with another network / contract | `EVIDENCE_NETWORK`, `ROLE_CONTRACT` |
| self-consistent candidate with another funding outpoint / value | `EVIDENCE_CONTEXT` |
| consistent candidate for a different covenant id | `COVENANT_MISMATCH` |
| missing evidence for a role | blocked status |
| any result at acceptance (closed gate) | `NOT_CONFIRMED` |
| forged result (flags, status or blockers altered) at acceptance | `NOT_CONFIRMED` |
| candidate `schema_version` given as bool, float or string | `CANDIDATE_SCHEMA` |

## 7. Findings requiring Codex decisions

1. **Placeholder constructor set.** The v2 bundle manifest (`b4e48882…`) binds
   placeholder constructor arguments, so every real authority key changes the
   scripts, the covenant ids and the manifest hash. A deployment needs a
   reviewed deployment-specific constructor set and compiled identity; the
   binding then refers to that identity, never to the placeholder test bundle.
2. **Governance key sharing.** The fixtures use a distinct placeholder
   governance key per contract (`shared_governance_key: false`); D1 implies one
   attestation key. Decide whether the key is shared or per contract; the
   validator supports both and reports the result.
3. **D5 wording.** Amend D5 as in section 3: an off-chain binding now;
   constructor-embedded ids only together with a concrete co-spend check.
4. **H-001 history.** The frozen canary record lacks the D5 reconstruction
   anchor (no funding outpoint recorded); a later external reconstruction from
   chain data is not claimed impossible. Historical evidence stays frozen and
   is not used as a D5 anchor.

## 8. Minimal proposed implementation (needs Codex approval, in order)

1. **Rust, offline (implemented in `bundle-v2-d5-offline-covenant-id`):**
   `prometheus-silverc-deployer calculate-covenant-id`. It returns the covenant id for
   (funding outpoint, genesis value, artifact). It reuses the output
   construction of `prepare_genesis` and the existing
   `kaspa_consensus_core::hashing::covenant_id`, with no keys and no network.
   Paths: `modules/silverc-deployer/src/lib.rs`, `src/main.rs`, deployer tests.
   The Rust pins stay unchanged. Its output is classified
   `NOT_CHAIN_EVIDENCE` and `NOT_DEPLOYMENT_AUTHORIZATION`.
2. **Evidence capture (implemented as a candidate in `bundle-v2-d5-evidence-capture`;
   acceptance stays blocked until the trusted-source model is decided):** see
   section 9.
3. **Python binding:** prepared without activation in
   `bundle-v2-d5-binding-alignment`. The draft now consumes Rust candidates,
   bound to the plan, with a cross-language fixture
   (`modules/silverc-deployer/tests/fixtures/d5-evidence-candidate.synthetic.json`).
   Still open after the independent security review and the trusted-source
   decision: replace `RECOMPUTE_BLOCKER` with the call to step 1 and move the
   validator from draft to tooling behind the bundle registry.
4. **Runtime acceptance (separate brief):** client rule observation accepts
   only covenant ids from a confirmed binding, with role
   (`modules/client/src/blockchain/rule_observation.rs`, step 7 of
   `verify_observation_shared`).

## 9. D5 evidence candidate (step b)

`prometheus-silverc-deployer observe ... --d5-evidence-candidate-out <path>`
writes, in addition to the unchanged `NodeObservation`, a separate document
`prometheus.silverc.d5.genesis_evidence_candidate` (schema 1). Without the
flag, `observe` behaves exactly as before. v1 requests, signing requests,
receipts and the historical H-001 evidence are not changed.

| Part | Source | Fields |
|---|---|---|
| `preparation` | validated preparation inputs (`validated_preparation_inputs_not_chain_proof`) | network id, contract name, request and signing-request hashes, funding outpoint, genesis value, contract output index, contract script public key, calculated covenant id, expected deploy tx id |
| `observed` | typed `get_utxos_by_addresses` entry from the configured node (`configured_node_get_utxos_by_addresses_typed_entry`) | outpoint, amount, script public key, covenant id, block DAA score, coinbase flag (strict allowlist) |
| `observed_virtual_daa_score`, `daa_depth` | `get_block_dag_info` from the same node | — |
| `observed_snapshot_sha256`, `candidate_sha256` | canonical JSON (sorted keys, compact) SHA-256 | — |

- The status is always `OBSERVED_NOT_INDEPENDENTLY_CONFIRMED`. The
  classification is `NOT_CHAIN_PROOF`, `NOT_D5_ACCEPTANCE` and
  `NOT_DEPLOYMENT_AUTHORIZATION`. The trust model is
  `single_operator_configured_node` with `independent_confirmation: false`.
- The trust model lists the missing checks: a second independent node or
  explorer, a reviewer-captured response, a block hash/header cross-check, and
  network identity independent of the endpoint.
- The snapshot is a normalized allowlist of the typed entry, not the complete
  raw wire response. Its hash proves integrity and internal consistency only.
- Not stored: RPC endpoint, deployer or contract address, headers, logs,
  timestamps, and wallet or operator metadata.
- `verify_d5_evidence_candidate(candidate, validated_context)` requires the
  externally validated signing request returned by `rebuild_and_verify`.
  There is no optional or default bypass. Every exported preparation field
  must equal that context:
  - network, contract, request and signing-request hashes;
  - funding outpoint, value and output index, which must be the fixed genesis
    index 0;
  - script, calculated covenant id and expected deploy txid.

  Authority never comes from hashes carried inside the candidate. The verifier
  then checks:
  - the fixed schema, status, classification and trust model, and the
    documented sources;
  - the recalculated covenant id;
  - the observed outpoint, value, script and covenant id;
  - not coinbase;
  - DAA chronology: a genesis DAA score above the observed virtual DAA score
    is rejected, not clamped to depth 0;
  - DAA depth and both hashes.

  The result is context-bound consistency only. It is still not independent
  chain proof or D5 acceptance.
- Parsing rejects unknown, duplicate and missing fields.
- The CLI runs the collision gate before any read. The candidate is created
  exclusively and before the observation is written; an existing candidate
  aborts the command.
- The Python draft evidence format (section 4) is still a design draft;
  aligning it with this candidate belongs to step 3.

Non-goals: no signing, wallet, chain, deployment export, production or Mainnet
claim; no change to H-001, proof, toolchain or Rust pins, tokenomics, slash or
commit-reveal.
