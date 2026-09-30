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
state, over the digest of `(proposal_id, validator_set_root, votes_for,
votes_against, participants, tally_nonce)`. The contract stores the last
`tally_nonce` to reject certificate replay.

Why: a per-voter nullifier set does not fit bounded singleton state, and
cross-contract membership lookups are impossible. The trust in the attestation
key is explicit and owner-controlled today; replacing it with a threshold of
independent validator keys is part of milestone M4 (Guardian
decentralization), not of this bundle.

### D2 — Trusted time (PRM-15)

Every caller-supplied `block_height` used for a rate limit or window is
replaced by chain-bound checks: stored thresholds are DAA scores and
transitions `require(tx.time >= threshold)` (cooldowns, tuning interval,
finalize-after-voting-end). Upper bounds (ballots before the voting end) are
enforced by the tally certificate in D1, whose ballots carry ledger time. The
GovernanceAutoTuning ratchet can then advance at most once per real interval.

### D3 — Bond custody and slashed-fund destination (PRM-16, PRM-19, PRM-24)

The bond stays stake-internal (as in the `.sil` port): no separate payout on a
valid reveal. Slashing must move value: every slashing transition requires an
output that pays exactly the slashed amount to a provably unspendable script
(burn), checked with output-amount introspection, and the continuing validator
output must carry `previous amount - slashed amount`. Donation and withdrawal
transitions get the same value-conservation checks.

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
participation rule.

### D5 — Cross-contract identity binding (PRM-21, PRM-25 genesis anchor)

There are no runtime cross-contract calls. Each state contract receives the
covenant IDs of the contracts it trusts (and the attestation key) as
constructor arguments; one deployment manifest lists every covenant ID and is
part of the reviewed release bundle. Off-chain tooling accepts only states whose
genesis covenant ID appears in that manifest, which closes the lookalike
covenant gap for GuardianReputation.

### D6 — Validator cooldown (PRM-35)

Decided earlier today: 7 days = 6,048,000 blocks at 10 BPS, longer than the
1-day voting period (`.fleet/reports/prm35-cooldown-decision.md`). The re-
registration bypass (PRM-23) does not exist in the `.sil` model (no
`register()`); the fund-lock dead state (PRM-13) gets an exit transition for
`active = false, withdraw_request_block = 0` that starts the cooldown.

### D7 — Source of truth: `.sil`, not `.ss`

The current-silverc `.sil` fixtures are the only deployment source. The legacy
`.ss` files stay frozen as historical reference: not built, deployed or fixed.
`.ss`-only findings (PRM-16, 17, 18, 20, 21, 22, 23, 24, 26) are closed as not
on the deployment path once their intent is covered by the D1–D5 child tests;
`.ss` ↔ `.sil` divergences (PRM-25) are resolved in favor of `.sil`, with the
status enum documented for indexers.

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

## Review repair (2026-09-30, draft branch `agent/claude/bundle-v2-review-repair`)

Codex's review of the first draft (verdict: changes) found three gaps; the draft now implements:

- **Attestation binding (D1/D4):** every attestation digest is versioned (`…-v2` domains) and
  binds the deployment instance (`OpInputCovenantId` of the spent covenant input), the per-
  contract proposal id as replay nonce, and the complete proposal content (RuleStorage: guardian
  key, threat hash, rule type, CID, confidence; CommunityDonations: recipient, amount, purpose,
  proposer; DevIncentivePool: developer, contribution/description hashes, lines, complexity,
  amount, proposer). Tallies additionally bind the consensus session start/end. A proposal id
  finalizes exactly once because the status leaves PENDING; it is the replay nonce D1 promised,
  so no extra nonce field is needed. Cross-instance, substituted-content, other-session and
  replayed attestations are rejected by runtime tests.
- **Consensus time (D2):** no voting window or tuning interval depends on a caller-chosen height.
  Windows start at the DAA score of the covenant UTXO created by the proposal
  (`OpTxInputDaaScore`), and finalization requires `tx.time >= start + window` (CLTV against the
  transaction lock time, which consensus only accepts once the chain has reached it). Exact
  semantics: the start is the DAA score of the block that accepted the proposal transaction;
  intermediate donations in CommunityDonations record that value instead of moving it.
  GovernanceAutoTuning: `autoTune` stores an "anchor pending" marker and the permissionless
  `settleTuning` records the exact inclusion DAA score while the tuning output is unspent. Until
  settled, the next tuning is measured from the spent UTXO's DAA score, an upper bound of the
  tuning time: tuning can be delayed by intervening metric reports but never happens faster than
  one interval of consensus time, and historical catch-up is impossible.
- **Terminal rejection (D4):** every attested tally is terminal. Zero or low participation, or
  approval below 6,700 bps, ends REJECTED in RuleStorage, CommunityDonations and DevIncentivePool,
  so the single proposal slot is released; a new submission after rejection is tested.

Status: still **proposed** until Codex's security review of the repair.

## Open risks

- The attestation key in D1/D4 is a single owner-controlled trust point until
  M4; this must be stated publicly wherever voting is described.
- Burning slashed KAS is irreversible by design. Child issue 1 must first
  verify that Kaspa relay/standardness rules accept the chosen unspendable
  output form and its storage mass; if not, the fallback is a covenant-locked
  output that no key can spend, reviewed the same way.
- SilverScript v1.0.0 adds stricter resource and initial-state validation; the
  bundle v2 port should target it once upstream aligns on a rusty-kaspa release
  (`.fleet/reports/a8u1-kaspa-silverscript-upgrade-inventory.md`).
