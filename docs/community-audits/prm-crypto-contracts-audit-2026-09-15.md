# Prometheus — Cryptography & Contracts Deep Audit

- **Series:** Collateral Web3 Open Audits
- **Date:** 2026-09-15
- **Target:** NeaBouli/prometheus- @ `8b5da58a34172062cf644db52ba459385d151562`
- **Scope:** 6 Silverscript `.ss` architecture contracts, 7 `.sil` covenant state fixtures (incl. deployed H-001 canary), BIP340 paths, BN254/Arkworks Groth16 v2 binding, commit-reveal formula, covenant-ID derivation
- **Method:** full read by a contracts deep-recon agent + lead verification of every finding at file:line; all four commit-reveal vectors independently recomputed by the agent and spot-recomputed by the lead; no chain calls
- **Repo boundaries respected (AGENTS.md):** no emergency-stop proposal, no `slash()` access-control redesign, no commit-reveal formula change — every contract recommendation is framed as **owner decision**
- **Register:** PRM-13 … PRM-27 (this report) — **0 Critical / 6 High / 6 Medium / 2 Low / 1 Info**

---

## Executive summary — and the severity context that matters

Only `ValidatorStakingH001.sil` is deployed: an 18-line **stateless** preimage verifier on Testnet-10 holding no state and no value (checked: no findings — PRM-27). Everything else is pre-deployment: the six `.ss` files are pre-Toccata architecture references, the six `*State.sil` files are port fixtures runtime-tested but not deployed. **Every High in this report is therefore a design-phase finding rated "if deployed as written" — nothing is live-exploitable today.** That is precisely when these findings are cheapest to act on, and the project's own gate list already anticipates most of them.

The cryptography that *is* live-adjacent is excellent: the commit-reveal formula is byte-exact across Rust, Python and `.sil` (four vectors independently recomputed, including `u64::MAX` and negative-value rejection tests); BIP340 verification runs through libsecp256k1 with dual-signature proof-of-possession rotation; the Groth16 v2 binding enforces canonical key/proof re-serialization and exact public-input counts.

## Severity table

| ID | Severity | Title |
|----|----------|-------|
| PRM-13 | High¹ | `.sil`: permanent fund-lock dead state after slashing below MIN_STAKE (`ValidatorStakingState.sil`) |
| PRM-14 | High¹ | `.sil`: voting transitions lack validator membership and double-vote protection (3 contracts) |
| PRM-15 | High¹ | `.sil`: all time inputs caller-supplied, not chain-verified (systemic rate-limit bypass) |
| PRM-16 | High¹ | `.ss`: vote bond never collected but paid out on valid reveal — pool drainage |
| PRM-17 | High¹ | `.ss`: `submitProposal` has no guardian authorization; attacker-chosen `guardian_pubkey` → reputation griefing |
| PRM-18 | High¹ | `.ss`: no participation quorum — 1-of-N approval accepts a rule |
| PRM-19 | Medium¹ | `.sil`: covenant value vs state accounting gap (systemic across fixtures) |
| PRM-20 | Medium¹ | `.ss`: `deposit()` unauthenticated accounting inflation (pre-acknowledged in-repo) |
| PRM-21 | Medium¹ | `.ss`: cross-contract authorization wiring broken; contract addresses undeclared in 5 of 6 |
| PRM-22 | Medium¹ | `.ss`: `auto_tune` calls non-existent `getActiveCount`; tuned parameters unread by staking contract |
| PRM-23 | Medium¹ | `.ss`: cooldown bypass via re-registration |
| PRM-24 | Medium¹ | `.ss`: slashed funds have no destination; FP-oracle stub is a one-way ratchet (known Q-003) |
| PRM-25 | Low¹ | `.ss`↔`.sil` semantic divergences (status-enum shift, single-slot overwrite, genesis-anchor dependence) |
| PRM-26 | Low¹ | `.ss` precision/cluster: commit-phase binding gaps, overflow-semantics divergence Rust↔contract, formula truncation |
| PRM-27 | Info | Deployed H-001 canary verified clean; commit-reveal 64-bit salt hiding assumption noted |

¹ rated "if deployed as written" — design-phase findings on pre-deployment artifacts; nothing here is live on any network.

---

## PRM-13 — High¹ — `.sil`: permanent fund-lock dead state after slashing below MIN_STAKE

**Evidence (lead-verified):** `modules/contracts/silverc/ValidatorStakingState.sil` — `slashInvalidReveal` sets `active: remaining_stake_kas >= MIN_STAKE_KAS` (`:126`). Once `active=false` **and** `withdraw_request_block == 0`, every path is closed: `commitVote` (`:64,66`), `revealVote` (`:90`), `slashInvalidReveal` (`:114`), `requestWithdraw` (`:141,143`) all `require(prev_state.active)`, while `completeWithdraw` (`:163-166`) requires `!prev_state.active` **and** `prev_state.withdraw_request_block > 0`. No reachable transition exists → the validator's covenant UTXO is bricked, stake locked forever. The `.ss` version handles this correctly (`withdraw()` only requires `stake_kas > 0`, `ValidatorStaking.ss:180`). The runtime tests do not cover this state (coverage list `silverc/README.md:92-105`).

**Recommendation (owner decision):** add an exit transition for the `(active=false, withdraw_request_block=0)` state before any deployment; add the state to the runtime coverage list.

## PRM-14 — High¹ — `.sil`: voting lacks validator membership and double-vote protection

**Evidence (lead-verified):** `RuleStorageState.sil:117-153`, `DevIncentivePoolState.sil:105-139`, `CommunityDonationsState.sil:118-152` — `voteOnProposal`/`voteGrant`/`voteDisbursement` take `validator_pk` as a free input and require only `checkSig(validator_sig, validator_pk)`. There is no check that the key is a registered/active validator (the `.ss` versions do `is_active_validator(msg.sender)` via cross-contract call — impossible in the singleton covenant model), and **no per-voter replay state** (the `.ss` `*_voters` maps have no counterpart). Any key can vote; the same key can vote repeatedly across successive singleton transitions to reach quorum alone.

**Impact (if deployed):** one actor drives any proposal/grant/disbursement to acceptance. The design presumably intends off-chain orchestration to enforce membership — but as written the on-chain artifact does not constrain it.

**Recommendation (owner decision):** hard pre-deployment gate — define the membership-proof mechanism (e.g., validator-set covenant cross-reference or oracle-attested ballot) and per-voter nullifier state.

## PRM-15 — High¹ — `.sil`: all time inputs caller-supplied, not chain-verified

**Evidence (lead-verified):** every `.sil` transition takes `block_height` as a plain input — `GovernanceAutoTuningState.autoTune` only checks `block_height >= last_tuning + TUNING_INTERVAL_BLOCKS` (`:83`), so a fabricated far-future height ratchets parameters step-by-step in consecutive transitions (confidence→floor, stake→floor/ceiling, reward→ceiling); the same applies to RuleStorage voting windows (vote after end with a low height; finalize early with a high one — finalize additionally requires governance sig, limiting impact there), DevIncentivePool/CommunityDonations voting ends, and `ValidatorStakingState.committed_at_block`/`last_vote_block` (arbitrary values, including future).

**Recommendation (owner decision):** bind time checks to covenant runtime introspection (tx locktime/DAA score) if available, or treat all on-chain rate limits as advisory and enforce them in the (already disciplined) operator tooling.

## PRM-16 — High¹ — `.ss`: vote bond never collected but paid out on valid reveal

**Evidence (lead-verified):** `ValidatorStaking.ss:81-101,119-135` — `commitVote` validates `bond >= stake*10/100` and `bond <= stake_kas` and records `bond_kas`, but there is **no `tx.value` check and no transfer** locking the bond; on valid reveal `transfer(msg.sender, vc.bond_kas)` (`:132`) pays KAS out of the contract balance — i.e. out of *other validators' stakes*. On invalid reveal the "penalty" is only an accounting deduction. Every honest reveal drains the pool by up to 10% of the validator's stake; bond economics are inverted.

**Recommendation (owner decision):** define bond custody (escrow via `tx.value`, or stake-internal accounting with no payout on reveal).

## PRM-17 — High¹ — `.ss`: `submitProposal` unauthenticated; attacker-chosen `guardian_pubkey`

**Evidence (lead-verified):** `RuleStorage.ss:71-108` — the comment says "Called by guardians via the reputation contract" but there is **no caller check**, and `guardian_pubkey` is a free parameter. Combined with `finalizeProposal` calling `call(GUARDIAN_REPUTATION_CONTRACT, "proposal_rejected", p.guardian_pubkey)` (`:173`), anyone can submit a doomed proposal naming a victim guardian to halve their reputation — or name themselves and farm `proposal_accepted` (see PRM-18).

## PRM-18 — High¹ — `.ss`: no participation quorum — 1-of-N approval accepts a rule

**Evidence (lead-verified):** `RuleStorage.ss:139-143` — `finalizeProposal` requires only `total_votes > 0` and `approval = votes_for*10000/total_votes >= 6700`: a proposal with one "for" vote and zero against finalizes ACCEPTED (rule stored, KRC20 minted at `:162`, guardian reputation boosted). A single active validator (10,000 KAS stake) can unilaterally accept rules, including their own. `DevIncentivePool.ss:112-133` and `CommunityDonations.ss:125-143` use a fixed `QUORUM_VOTES = 10` — an absolute number, not a fraction of the active set (low-participation exploitable when the set is small; sybil-scalable if it grows).

**Recommendation (owner decision):** minimum-participation threshold as a share of the active validator set.

## PRM-19 — Medium¹ — `.sil`: covenant value vs state accounting gap (systemic)

**Evidence:** the `.sil` fixtures model balances as state ints; nothing in the covenant scripts binds value movement to accounting. `ValidatorStakingState.sil`: bond is state-only (`:69-70`); `slashInvalidReveal` decrements tracked stake (`:121`) while output values are unconstrained — if the "output 0 preserves the covenant amount" deployer pattern applies (`silverc/README.md:513-514`), slashing has **zero economic effect** (full value exits at `completeWithdraw`, whose outputs are unrestricted beyond `next_states.length == 0`). `CommunityDonationsState.sil:50-77`: `donateKas` increases `pool_balance_kas` by a caller-supplied `amount` with only a donor self-signature — unbacked accounting. `DevIncentivePoolState.sil`: no deposit path; pool exists only as genesis-set state.

**Recommendation (owner decision):** explicit covenant-value transition spec (which outputs carry what value per transition) before deployment.

## PRM-20 — Medium¹ — `.ss`: `deposit()` unauthenticated accounting inflation

**Evidence (lead-verified):** `DevIncentivePool.ss:146-149` — `deposit(amount)` does `pool_balance_prom += amount` with no `tx.value`/transfer check and no caller restriction. **Pre-acknowledged** in-repo (`silverc/README.md:671-672`, "known legacy deposit() ACL question remains a deployment/orchestration decision") — recorded here for register completeness; must be closed before any deployment holding real PROM.

## PRM-21 — Medium¹ — `.ss`: cross-contract authorization wiring broken

**Evidence:** `RuleStorage.ss:165,173` calls `GuardianReputation.proposal_accepted/proposal_rejected`, which require `msg.sender == GOVERNANCE_CONTRACT` (`GuardianReputation.ss:98,120`) — RuleStorage calls as *itself*, so calls either revert (DoS of every finalize) or silently no-op (reputation never updates), depending on runtime semantics. Additionally `GOVERNANCE_CONTRACT`/`GUARDIAN_REPUTATION_CONTRACT`/`VALIDATOR_STAKING_CONTRACT` are **never declared as state** in 5 of 6 contracts (only `ValidatorStaking.ss:51-52` declares its two) — the deployment-time binding is unspecified.

## PRM-22 — Medium¹ — `.ss`: `auto_tune` calls a non-existent function; tuned params unread

**Evidence:** `GovernanceAutoTuning.ss:128-130` calls `VALIDATOR_STAKING_CONTRACT.getActiveCount` — ValidatorStaking exposes only `getValidator/getStake/isActive` (`:204-216`); `auto_tune()` would revert on every execution. Related: `auto_tune` writes `params.min_stake_kas`, but ValidatorStaking uses the hardcoded `const MIN_STAKE_KAS` (`:35`) — the tuning loop writes parameters nobody reads.

## PRM-23 — Medium¹ — `.ss`: cooldown bypass via re-registration

**Evidence:** `ValidatorStaking.ss:60-75,178-201` — `withdraw()` step 1 sets `active=false` and records `withdraw_requests[msg.sender] = block.height`; `register()` only requires `!active`, so a validator can re-register with fresh stake while a withdraw request is pending; `withdraw_requests[msg.sender]` is **not cleared**, and the second `withdraw()` call settles against the *old* (already elapsed) request block — immediate payout of the new stake, bypassing the cooldown.

## PRM-24 — Medium¹ — `.ss`: slashed funds stranded; FP-oracle stub one-way ratchet

**Evidence:** `ValidatorStaking.ss:121-127,158-174` — both the invalid-reveal penalty and `slash()` only decrement `stake_kas`; the KAS remains in the contract with no destination accounting (stranded, or subsidizing the PRM-16 payouts). Destination definition = owner decision (distinct from the owner-locked `slash()` ACL). Separately, `GovernanceAutoTuning.ss:117-125` `oracle_get_fp_rate()` returns constant 0 → the lowering branch fires every interval, ratcheting `min_confidence_ki` to the floor over ~35 intervals (known Q-003, `memory/AUDIT.md:265`; the `.sil` port resolves it with oracle-signed metrics — ensure the stub can never reach production).

## PRM-25 — Low¹ — `.ss`↔`.sil` semantic divergences

- Status enums shifted: `RuleStorage.ss:46-48` (0=PENDING,1=ACCEPTED,2=REJECTED) vs `RuleStorageState.sil:31-34` (0=EMPTY,1=PENDING,2=ACCEPTED,3=REJECTED) — off-chain indexers written against the `.ss` encoding will misread finalized states.
- `RuleStorageState.sil` is a single-slot machine: accepted rule data is **overwritten** by the next `submitProposal` (only chain history preserves old rules); one-pending-proposal-at-a-time is a throughput/griefing bottleneck.
- `GuardianReputationState.sil` initial state is constructor-supplied — authenticity depends entirely on genesis covenant-ID/P2SH anchoring; a lookalike covenant with forged initial reputation is indistinguishable without the genesis-anchor registry.
- `ValidatorStakingState.sil` has no governance `slash()` path and no `register()` (genesis-initialized) — divergence from the `.ss` lifecycle.
- `DevIncentivePoolState.sil` uses `byte[32]` hashes for contribution/description vs `.ss` strings (off-chain reveal needed).

## PRM-26 — Low¹ — `.ss` precision cluster

- Commit phase lacks proposal binding and timing windows (`ValidatorStaking.ss:81-139`): no proposal-exists/window check at commit, no reveal deadline, same-block commit+reveal allowed, no forfeit path for never-reveal (moot given PRM-16).
- Overflow-semantics divergence: `.ss` `penalty = stake*percent*multiplier/100` plain uint64 (`:158-161`) vs Rust `saturating_mul` (`slashing/mod.rs:30`) — the "bit-for-bit identical" claim (`mod.rs:8-9`) is falsifiable at the boundary (needs ~6.1e16 sompi — economically unreachable, but the equivalence claim should be precise). `commit.rs:73`/`reveal.rs:62` also non-saturating.
- `GuardianReputation.ss:89` voting-power computes `(rep/100)² * compute/1000` — truncation makes the documented quadratic formula stepped (rep=1999 → 361 vs true ≈399).
- `RuleStorage.ss:100` window reset `>` vs `>=` off-by-one; `CommunityDonations.ss:146-154` O(n) donor scan + uncapped `purpose`; `DevIncentivePool.ss:52-85` no proposer bond (grant spam); mixed time sources (`block.height` vs `block.timestamp`) across contracts; `VALIDATOR_QUORUM = 6700` documented as "2/3 majority" (is 67%, tie accepts); implicit `sha256(proposal_id || msg.sender)` concatenation (`:60,117`) — same ambiguity class as the flagged H-001 TODO.

## PRM-27 — Info — Deployed H-001 canary clean; salt-entropy assumption

`ValidatorStakingH001.sil` (the only deployed artifact): 18-line stateless verifier for `sha256(vote_byte || byte[8](salt) || byte[8](block_height)) == expected`; holds no state and no value; negative `salt`/`block_height` produce valid-but-different preimages (no `>= 0` guard in the canary — the **deployer-side** boundary correctly restricts deployment values to `0..=i64::MAX`, `commit.rs:21,126-140`, and negative-value rejection is runtime-tested). No finding in the canary itself. Note: the 64-bit salt gives limited hiding against a well-resourced observer brute-forcing a 1-bit vote (2⁶⁴ work) — document the assumption; the (validator, proposal) binding comes from contract storage keying, not the preimage (formula is CI-pinned to the `.sil` fixture, `ci.yml:63-73`).

---

## Verified strengths (evidence-checked)

- **Commit-reveal formula byte-exact** across Rust (`validator-node/src/voting/commit.rs:146-156`), Python (`scripts/verify_silverc_h001.py:419-428`) and `.sil` (`ValidatorStakingState.sil:40-44`) — all four vectors (incl. `u64::MAX`) independently recomputed; signed-int boundary enforced via `build_silverc_checked` with explicit typed errors.
- **BIP340 verification is libsecp256k1** (coincurve) in every Python path (`signed_ballots.py:636-643`, `observable_approval.py:224-231`, `guardian_membership_transition.py:344-346,483-494`) — rotation is dual-signature (old-key authorization + new-key proof-of-possession) with key-reuse prevention.
- **Groth16 v2 binding:** canonical compressed BN254 keys/proofs with full re-serialization, `gamma_abc_g1.len() == public_input_count+1` enforced at load, all-invalid → `Ok(false)`, injective public-input encoding (2×16-byte BE halves of a domain-separated statement digest).
- **Slashing engine:** multiplier `min(3, count/3+1)`, penalty `min(stake*percent*mult/100, stake)`, deactivation below MIN_STAKE — tests cover escalation boundaries (2→3, 6, 9, 100), 100%-cap, zero edge cases, cross-verified with the `.ss` numbers.
- **Constant-time discipline:** `subtle` in Rust (`observable_approval.rs:193-200`, `observable_bundle.rs:363`), `hmac.compare_digest` in Python — exactly where attacker-probeable compares happen.
- **Deployer covenant rigor** (see full-scope report): consensus `covenant_id()` derivation, SIG_HASH_ALL with `authorizing_input=0`, storage-mass commitment, deterministic interop vectors pinning txid/covenant/sighash/masses.
- **CommunityDonations.ss** is the cleanest `.ss` contract: `tx.value`-verified donations with correct accounting and balance re-check at execution.
