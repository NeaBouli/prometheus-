# Handover / TODO — Claude, 2026-10-03

Living status list for the contract-v2 / D5 line (issue #276). Updated at every
status change. Codex owns review, integration, merge and release decisions.

## Delivered blocks (all reviewed by Codex unless noted)

| Block | Branch | Head | Hosted CI / Security | Status |
|---|---|---|---|---|
| bundle-v2-profile-separation | agent/claude/bundle-v2-profile-separation | af24d3f | 36803527002 / 36803530512 green | accepted with correction |
| bundle-v2-early-gate-correction | agent/claude/bundle-v2-early-gate-correction | 506cf01 | 36808119490 / 36808123049 green | accepted |
| bundle-v2-d5-genesis-binding-design | agent/claude/bundle-v2-d5-genesis-binding-design | eaf8eb7 | none (design block) | working basis |
| bundle-v2-d5-offline-covenant-id | agent/claude/bundle-v2-d5-offline-covenant-id | ea73277 | 36811470926 / 36811473498 green | accepted |
| bundle-v2-d5-evidence-capture | agent/claude/bundle-v2-d5-evidence-capture | 20ff442 | none on this head | corrected below |
| bundle-v2-d5-capture-context-correction | agent/claude/bundle-v2-d5-capture-context-correction | 61549b1 | 36814029226 / 36814032876 green | accepted |
| bundle-v2-d5-binding-alignment (C1) | agent/claude/bundle-v2-d5-binding-alignment | 2595ce8 (+docs 95aa512, f6d3dc6) | not dispatched | reviewed by Codex 15:21Z: two findings, fixed below |
| bundle-v2-d5-alignment-closed-gate | agent/claude/bundle-v2-d5-alignment-closed-gate | 684a4d5 (code) (docs 1c96d98) | 37134471451 / 37134474481 green | accepted |
| g1-receipt-mypy-annotation | agent/claude/g1-receipt-mypy-annotation | 1e0849d (docs f090c35) | not dispatched | accepted by Codex |
| landing-status-20261004 (+correction) | agent/claude/landing-status-20261004-correction | 417e2fb | not dispatched | waiting for Codex UI review (evidence ~/agent-fleet/evidence/prometheus/landing-status-20261004-correction/) |
| c2-k1-followup | agent/claude/c2-k1-followup | 994f017 | not dispatched | **waiting for Codex review** |

## Who waits for whom

- **Codex**: review C2 and the landing correction; coordinate one hosted run for the new runtime regressions.
- **Kimi (K1)**: done 2026-10-03 on 61549b1 (Gio approved the transfer):
  changes requested; follow-up C2 delivered by Claude.
- **Claude**: C3 = Zelcore check once a link or brief exists; site-wide October claim
  reconciliation after C2 (Codex decision).
- **G1**: done by Claude, accepted by Codex.

## Open decisions

- Gio: K1 transfer approved 2026-10-03 (done).
- Codex: C2 decisions (optional donation bound, unused constants in next source revision, constructor counter bounds).
- Codex: trusted-source model for D5 evidence acceptance (Kimi K2 can draft variants).
- Codex: D1–D7 remain proposed; full contract security acceptance pending K1.

## Next tickets (in order, all gated)

1. K1 review → C2 fixes → one hosted CI/Security run.
2. Trusted-source model decision (K2 variants).
3. D5 step (c) activation: recompute via `calculate-covenant-id`, move the
   draft validator into tooling.
4. D5 step (d): client allowlist in `rule_observation.rs` (separate brief).
5. Deployment-specific constructor set and compiled identity (no placeholders).

## Guardrails that stay

No merge to main, no deployment, no chain/wallet/signing, v2 non-promotable,
H-001 evidence frozen, Rust release pins on v1.
