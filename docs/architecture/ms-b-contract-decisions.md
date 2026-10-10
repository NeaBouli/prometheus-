# MS-B Contract Decision Record (proposal)

Status: **proposed** by the Claude stand-in on 2026-09-30 under the owner's
delegation of technical decisions ("entscheide du"). It becomes binding only
after Codex's architecture review. It authorizes no code, deployment, or
public claim. Scope: issue #276 (audit PRM-13..27, PRM-35). Hard constraints
kept: KAS/PROM separation, canonical Kaspa L1 Guardian reputation, current
`slash()` access control, the H-001 commit-reveal formula, and no emergency
stop.

## Capability baseline (pinned silverc `d25bd34`)

Verified in the pinned compiler source on 2026-09-30:

- `require(tx.time >= X)` compiles to `OP_CHECKLOCKTIMEVERIFY` (absolute lower
  bound against the transaction lock time, DAA score on Kaspa);
  `require(this.age >= X)` compiles to `OP_CHECKSEQUENCEVERIFY` (relative
  lower bound).
- Transaction introspection exists for inputs and outputs, including input and
  output amounts (`OpTxInputAmount`, `OpTxOutputAmount`) and input DAA score.
- Signatures: `checkSig` and `checkSigFromStack` (BIP340 over a 32-byte
  digest); no native M-of-N opcode, so thresholds are bounded repeated checks.
- Singleton covenants cannot call other contracts at runtime.

Consequence: on-chain logic can enforce **lower** time bounds, **value
conservation**, and **signature** checks. It cannot enforce upper time bounds
("before the deadline") or query another contract's state.

## Decisions

### D1 — Validator membership and per-voter replay (PRM-14)

Per-vote transitions that accept a free `validator_pk` are removed from
RuleStorage, DevIncentivePool and CommunityDonations. Voting happens off chain
through the existing canonical membership source and the BIP340 signed-ballot
replay ledger (GH-147, GH-242, GH-253), which already enforce one ballot per
member per session. A finalize transition accepts one **tally certificate**
signed with `checkSigFromStack` by the attestation key stored in the contract
state. The delivered v2 digests bind the versioned domain, covenant instance,
proposal/grant/disbursement ID, full content, session anchor, tally counts,
active-set size and root. Pending-state consumption makes each tally terminal;
there is no separate stored `tally_nonce`. Exact preimages: contract README.

Why: a per-voter nullifier set does not fit bounded singleton state, and
cross-contract membership lookups are impossible. The trust in the attestation
key is explicit and owner-controlled today; replacing it with a threshold of
independent validator keys is part of milestone M4 (Guardian
decentralization), not of this bundle. The off-chain foundations do not prove
an operated contract-attester integration or independently trusted membership.

### D2 — Trusted time (PRM-15)

The v2 draft anchors proposal windows and tuning at spent-UTXO consensus DAA
scores, enforced by CLTV lower bounds; withdrawal uses relative covenant age.
Donation labels, oracle metadata and the unchanged H-001 commitment height
are not interchangeable with those anchors. Upper ballot deadlines remain
an off-chain attester obligation, not an independently proven chain check.
`autoTune` uses an anchor-pending marker and `settleTuning`, not a caller height.

### D3 — Bond custody and slashed-fund destination (PRM-16, PRM-19, PRM-24)

The bond stays stake-internal (as in the `.sil` port): no separate payout on a
valid reveal. Slashing must move value: every slashing transition requires an
output that pays exactly the slashed amount to a provably unspendable script
(burn), checked with output-amount introspection, and the continuing validator
output must carry `previous amount - slashed amount`. Donation and withdrawal
transitions get the same value-conservation checks.

Feasibility (pinned silverc tutorial and compiler): `tx.inputs[this.activeInputIndex].value`,
`tx.outputs[i].value` and `tx.outputs[i].scriptPubKey` compile to `OpTxInputAmount` /
`OpTxOutputAmount` / output-script introspection, so a transition can require
`tx.outputs[0].value == tx.inputs[this.activeInputIndex].value - slashed_sompi` and pin the burn
output script. Prerequisite: the state field `stake_kas` must equal the covenant UTXO value
(1 KAS = 100,000,000 sompi) from genesis on, so the deployer's genesis output value has to be
derived from the initial stake instead of an operator-chosen amount.

Why burn: routing slashed KAS to a governance- or treasury-controlled pool would
let the parties who trigger slashing profit from it. Burning removes that
conflict of interest and keeps KAS/PROM separation untouched.

### D4 — Proposal authorization and quorum (PRM-17, PRM-18)

A proposal is accepted on chain only with an attested submission naming a
Guardian key that the canonical membership source lists at that time (same
certificate mechanism as D1); a free `guardian_pubkey` parameter is not
accepted. Finalization requires **both** participation of at least 50 % of the
active validator set snapshot (`validator_set_root`) **and** approval of at
least 6,700 basis points of cast votes (ties at the threshold accepted, stated
explicitly). The fixed `QUORUM_VOTES = 10` is replaced by the same
participation rule; the unused constants remain declared in this draft.
Membership/root provenance is asserted by the stored attestation key, not
independently verified by these contract-side threshold checks.

### D5 — Cross-contract identity binding (PRM-21, PRM-25 genesis anchor)

The delivered draft has no cross-contract calls, embedded trusted covenant
IDs or co-spend checks. D5 currently means off-chain identity calculation and
context-bound, observed-only consistency. State acceptance is unconditionally
closed; trusted-source/recomputation and client role binding remain later gates.
Future embedded IDs require a concrete reviewed check and acyclic deployment
policy; they are not proof of identity by themselves. See the D5 design and
unactivated trusted-source proposal below. No lookalike-closure claim is made.

### D6 — Validator cooldown (PRM-35)

The retained policy is 6,048,000 DAA-score units, nominally seven days at an
assumed 10 scores/s (`.fleet/reports/prm35-cooldown-decision.md`), not a wall-clock
guarantee. Rule voting uses 864,000 units (one nominal day); pool voting and
tuning use 604,800 units (16.8 nominal hours), not the same period. The re-
registration bypass (PRM-23) does not exist in the `.sil` model (no
`register()`); the fund-lock dead state (PRM-13) gets an exit transition for
`active = false, withdraw_request_block = 0` that starts the cooldown.

### D7 — Source of truth: `.sil`, not `.ss`

The current-silverc `.sil` fixtures are the only deployment source. The legacy
`.ss` files stay frozen as historical reference, outside the current compiled
deployment bundles; legacy static checks may still read them. Source migration
does not close findings automatically: PRM-16, 17, 18, 20, 21, 22, 23, 24, 26
require individual intent/evidence adjudication, including D1-D5 coverage.
PRM-25 divergences use the selected `.sil` bundle as the implementation source,
with status enums documented for indexers; audit acceptance remains separate.

## Implementation: one "contract bundle v2"

All outcomes ship as one reviewed revision because the silverc-deployer pins
the H-001 bundle manifest (`FULL_BUNDLE_MANIFEST_SHA256`): new fixture values,
new compiled expectation, a new closed deployment profile next to the frozen
H-001 profile, sample receipts, and docs. Proposed child issues (to be opened
by Codex):

1. ValidatorStakingState: D3 value conservation + burn output, D6 cooldown,
   PRM-13 exit transition, D2 time bounds.
2. RuleStorageState: D1 tally certificate, D4 attested submission and
   participation quorum, D2.
3. DevIncentivePoolState and CommunityDonationsState: D1, D4, D3 value checks
   for donations and disbursements.
4. GovernanceAutoTuningState: D2 interval bound (oracle-signed metrics stay).
5. GuardianReputationState: D5 genesis-anchor verification in tooling.
6. Deployment manifest + deployer profile v2 (D5), keeping H-001 verifiable.
7. Tests before any deployment: value conservation, membership/tally replay,
   time bounds, quorum edges (ties, 50 % participation), overflow, and
   cross-contract binding, per #276 acceptance.

## Open risks

- The attestation key in D1/D4 is a single owner-controlled trust point until
  M4; this must be stated publicly wherever voting is described.
- Burning slashed KAS is irreversible by design. Verified 2026-09-30: Kaspa
  mempool standardness accepts only PubKey, PubKeyECDSA and ScriptHash outputs,
  so the burn uses a P2SH of the always-failing script `OP_RETURN` (0x6a):
  standard, and anyone can check it is unspendable from the published preimage.
  Implemented and runtime-tested in the bundle v2 draft branch.
- SilverScript v1.0.0 adds stricter resource and initial-state validation; the
  bundle v2 port should target it once upstream aligns on a rusty-kaspa release
  (`.fleet/reports/a8u1-kaspa-silverscript-upgrade-inventory.md`).

## Later Draft Implementation Checkpoint (2026-10-10)

D1-D7 above remain proposals, not architecture/security/deployment acceptance.
The isolated C2 integration preview preserves the delivered v2-draft instead
of implementing the earlier prose literally. Current versioned attestation
digests, proposal/session/instance binding and terminal outcomes are described
in modules/contracts/silverc/README.md; older D1 nonce wording is not an ABI.

In particular, D5 currently implements off-chain identity calculation and
observed-only consistency, not embedded cross-contract IDs or runtime calls.
There are no current contract trust edges/co-spend checks. Future embedded IDs
require a reviewed concrete check and acyclic deployment policy; see
[the D5 design](d5-genesis-binding-design.md) and
[the unactivated K2 source model](d5-trusted-source-model.md).
Python acceptance remains unconditionally closed, v2 non-promotable and Rust
v1-pinned. Constructor/counter limits, governance-key topology, independent
full review and the prospective Codex Security gate remain open.
