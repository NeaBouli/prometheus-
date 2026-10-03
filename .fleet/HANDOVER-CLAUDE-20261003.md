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
| bundle-v2-d5-alignment-closed-gate | agent/claude/bundle-v2-d5-alignment-closed-gate | HEAD_PLACEHOLDER | not dispatched | **waiting for Codex review** |

## Who waits for whom

- **Codex**: review of the closed-gate correction; then one hosted CI/Security
  run on that head if he releases it.
- **Kimi (K1)**: independent read-only security review of contract v2 at
  61549b1 (`.fleet/tasks/bundle-v2-independent-security-review.md`).
  **Blocked on Gio**: Codex needs the explicit confirmation sentence for the
  code transfer to Kimi (see open decisions); no dispatch or workaround before.
- **Claude**: C2 = fix K1 findings once they arrive; C3 = Zelcore check once a
  link or brief exists.
- **Grok (G1)**: mypy annotation at `scripts/verify_silverc_deploy_receipts.py:162` — deferred by Codex while C1 writes (one writing worker at a time).

## Open decisions

- Gio: confirm in the Codex chat, verbatim: "Ich genehmige für K1 die Übermittlung der im bestehenden Review-Brief abgegrenzten Quellcode- und Testdateien an Kimi über `kimi-strong-worker`, ausschließlich read-only und ohne Secrets oder private Operatordaten."
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
