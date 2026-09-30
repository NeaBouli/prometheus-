id: bundle-v2-draft-validator-staking (MS-B D6 + PRM-13 + PRM-15 for withdrawal)
status: DRAFT — contract level verified; NOT integrable until the deployment-profile split below is designed and reviewed by Codex
worker: claude (Codex stand-in); branch agent/claude/contract-bundle-v2-draft (stacked on the stand-in branch)
contract changes (ValidatorStakingState.sil):
  - COOLDOWN_BLOCKS 100800 → 6048000 (7 days at 10 BPS).
  - completeWithdraw: caller-supplied block_height removed; `require(this.age >= COOLDOWN_BLOCKS)` → OP_CHECKSEQUENCEVERIFY on the withdrawal UTXO. Verified in pinned rusty-kaspa: consensus check_sequence_lock uses input.sequence (masked 32 bits) as a DAA-score delta from the UTXO's block_daa_score; the opcode requires script value <= input.sequence and a non-disabled sequence.
  - requestWithdraw: `require(prev_state.active)` removed (PRM-13 exit for a validator slashed below MIN_STAKE with no request), `block_height >= 0` → `> 0` (a zero marker created an unreachable inactive state — second dead-state path found).
  - validator-node COOLDOWN_BLOCKS mirrored (Rust/Silverscript constant consistency).
tests: pinned runtime/vector suite 58 passed (new: completeWithdraw accepts at sequence 6,048,000; rejects 6,047,999 and a disabled lock with UnsatisfiedLockTime; requestWithdraw accepts inactive slashed validator; rejects zero marker); validator-node 34; GH-283 gate flagged the change and the expectation was regenerated; sample receipts updated; docs switched to "7 days, on-chain relative lock (bundle v2 draft)"; claim/hygiene/site-css/memory gates pass.
local CI (contract-check + h001-silverc-runtime): 16/17 steps pass; FAIL at "Verify non-promotable H-001 canary deployment profile": scripts/test_silverc_canary_profile.py:121-127 and modules/silverc-deployer/src/lib.rs:54,671 require the request's full_bundle_manifest_sha256 == FULL_BUNDLE_MANIFEST_SHA256 (e6cec2aa… = v1 bundle). v2 manifest sha256 = 945c09fd…, archive 02aa0705….
open design (for Codex, release-gate owner):
  1. Split constants: H001_CANARY_BUNDLE_MANIFEST_SHA256 = e6cec2aa… (frozen, canary profile only) and FULL_BUNDLE_MANIFEST_SHA256 = v2 hash (full profile).
  2. The canary profile then cannot be regenerated from the current (v2) archive. Options: (a) CI verifies the committed H-001 evidence/request set instead of regenerating; (b) keep a reproducible v1 bundle build from pinned historical sources; (c) retire the canary profile in the deployer (evidence stays verifiable by the evidence verifiers). Recommendation: (a) — the canary is executed and non-promotable, so only its evidence needs to stay verifiable.
  3. Operator tooling must set input sequence >= 6,048,000 for completeWithdraw transactions (new requirement for the future transition operator; no such operator exists yet).
step 2 (value conservation + burn, MS-B D3), same branch:
  - requireStakeBacked(): covenant input value == stake_kas * 100,000,000 sompi; commitVote/revealVote/requestWithdraw require tx.outputs[0].value == input value.
  - slashInvalidReveal: output 0 = input − bond·10^8, output 1 = bond·10^8 to scriptPubKey 0x0000 aa20 blake2b(0x6a) 87 (P2SH of OP_RETURN). Kaspa mempool standardness allows only PubKey/PubKeyECDSA/ScriptHash outputs (mining/src/mempool/check_transaction_standard.rs), so an OP_RETURN output is not an option; the P2SH-of-OP_RETURN form is standard and anyone can verify it is unspendable from the published preimage.
  - tests: 63 passed (all 15 validator runtime tests moved to real stake-backed values; new: missing burn → InvalidOutputIndex, burn to spendable script, keeping slashed value, value leak on commit, unbacked stake).
  - new deployer requirement: genesis output value for ValidatorStakingState must equal the initial stake in sompi (today operator-chosen) — part of the profile/deployer v2 work.
  - storage mass: the burn output carries ≥ 1,000 KAS (10% bond of ≥ 10,000 KAS stake), far above storage-mass limits for small outputs.
not in this draft: D1/D4 tally certificates and quorum for RuleStorage/DevIncentivePool/CommunityDonations, D2 tx.time bounds for other transitions, D5 manifest/genesis binding.
