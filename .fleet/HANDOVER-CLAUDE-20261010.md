# Handover / TODO — Claude stand-in, 2026-10-10

Gio authorized Claude as temporary local orchestrator because Codex's token allowance ended
(Codex handover 2026-10-10 18:27Z; Codex standby). Merge, release and owner gates unchanged.

## Claim
- claim: ~/agent-fleet/standin/claims/019f3d96-5391-74c3-abfc-9395094e62e1.md (active)
- worktree: prometheus-master-plan-20260927-wt/claude-standin-20261010
- branch: agent/claude/prometheus-standin-20261010, base main 3cbb935
- coordination checkout (Codex, preserve dirty files): prometheus-master-plan-20260927

## Done (by Codex before handover, reused)
- main 3cbb935: #295 runtime fail-closed, #297 cooldown docs, #299 browser lifecycle (all green).
- Held drafts with green exact-head CI/Security: #293 24980e6, #296 649e495 (stacked docs), #298 2e455bc.
- Static constructor intake complete (7 contracts / 86 slots); D1-D7 conformance review complete.

## Done (Claude, 2026-10-10)
- ACK + claim; #276 readiness queue aligned (issuecomment-6100848279); brief
  .fleet/tasks/msb-constructor-semantics-review.md.
- msb-constructor-semantics-review DONE (analysis only): private report
  ~/Documents/Codex/prometheus-constructor-semantics-review-20261010.md (0600, sha256 a3615991…779c),
  all 86 slots; public generic summary #276 issuecomment-6101001254. No contract/pin change.

## Open / waiting
- Gio: constructor counter bounds + key topology, D1-D7 adoption, D5 trusted-source choice,
  remaining-diff independent-review transfer, Codex Security connection/scope.
- Review owed: complete v2 security acceptance at one agreed exact head.
- Disk ~1 GB free: no builds until space returns.

## Gio instruction 2026-10-10 (evening)
- Codex app closed / Codex paused. Claude works with its Claude Code terminal partners and Kimi 3
  (fully included from the next block). Pause before the next task block until Gio reactivates.

## Next (after reactivation)
1. Genesis checklist (machine-checkable, repo-only) from the constructor findings — candidate for Kimi.
2. #275 archival-fallback feasibility (read-only).
3. Owner decisions unchanged (see Open).

## Interim handover 2026-10-24 (Gio request: full takeover must be possible if Claude drops out)

Full owner-local packet: see the latest "PROMETHEUS — interim handover" pointer in the global Bridge.
Successor read order: that packet → Codex→Claude packet → this file → coordination PLAN/ACTION_LOG tail.

### Live state (verified 2026-10-24)
- main 3cbb935 unchanged since 2026-10-10; nothing in flight (no worker, CI, build, watcher). Claude PAUSED per Gio.
- Held, do not merge: #293 24980e6 (Draft), #296 649e495 (stacked on #293, held), #298 2e455bc (Draft).
  Not adjudicated: #286 2a62084, #269 2090529 (Draft, blocked by #271), #268 5960f1b (Draft).
- Open issues: #276 (MS-B tracker; readiness queue 6100848279, constructor summary 6101001254), #275 OPEN 6/7
  (archival fallback only), #283, #280, #279, #278, #277, #274, #271, #270, #267.

### Built by Claude (all pushed under agent/claude/*)
profile-separation af24d3f, early-gate-correction 506cf01, d5-genesis-binding-design eaf8eb7,
d5-offline-covenant-id ea73277, d5-evidence-capture 20ff442, d5-capture-context-correction 61549b1,
d5-binding-alignment f6d3dc6, d5-alignment-closed-gate 1c96d98, g1-receipt-mypy-annotation f090c35,
c2-k1-followup 3e94ce0, landing-status-20261004 095d047, landing-status-20261004-correction bc37515,
prometheus-standin-20260930 c377f1e (integrated #284/#285), prometheus-standin-20261010 (this branch).

### Next (after reactivation, in order)
1. Genesis checklist: machine-checkable checker for the constructor invariants (genesis zero-state, tuning
   anchor 0-or-real-DAA, tuning params within floor/ceiling, staking active == stake>=10000, unbacked counters 0,
   value backing for staking/donations), synthetic public fixtures + one negative test per invariant; no
   contract/pin/manifest change; v2 non-promotable; D5 gate closed.
2. #275 archival-fallback feasibility, read-only; no provider/server/wallet/trust assertion.
3. MS-B steps 3-5 only after owner decisions.

### Owner decisions open (hold)
Constructor values + counter bounds; role-to-key topology; D1-D7 adoption; D5 trusted source (#290 proposed);
51-file independent-review transfer; Codex Security connection/scope. Review owed: full v2 security acceptance
at one exact head.

### Workspace
Own worktrees clean/pushed: claude-standin-20261010 (active), claude-c2-k1-followup and claude-landing-20261004
(archivable). Coordination checkout: append-only, preserve 4 dirty files + 4 untracked briefs. Disk 4.8 GiB free:
reclaim before builds.
