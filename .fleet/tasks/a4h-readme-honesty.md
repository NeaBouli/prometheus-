# A4H — Public README and landing honesty reconciliation

Architecture boundary: `docs/architecture/MAP.md` public claims and
`modules/web` static status surface. Documentation only; no runtime or CI fix.

## Evidence and scope

- Read `/Users/gio/agent-fleet/community/prometheus-reddit/PROJEKT_BEFUND.md`
  and its handoff. Re-verify every cited claim against this current branch;
  stale findings receive no change.
- Correct only confirmed inconsistencies across `README.md`, `WHITEPAPER.md`,
  `index.html`, `roadmap.html`, FAQ/`llms.txt`, and existing claim gates/tests.
- Make Phi-3/ONNX, Guardian LLM, scanner/YARA, validator binary/network,
  Groth16 prover, PROM emission, KAS stake, lifecycle wiring, commands, sprint
  labels, versions, test counts, and completion percentages factual.
- Preserve and surface verified engineering strengths without converting them
  into production, decentralization, or rollout claims. Prefer durable wording
  over fragile counts; recompute any retained number on this exact branch.
- Issues #282 and #283 are separate. Do not touch Rust, Python, contracts,
  workflows, runtime behavior, SilverScript gates, tokenomics, or architecture.

## Acceptance

- All public surfaces agree with implemented/tested/testnet/target distinctions;
  no working command is claimed for a nonexistent binary or model deployment.
- Extend existing consistency tests only where required to prevent regression.
- Run public-claim and documentation-hygiene gates plus their complete tests.
- For visible HTML changes run the frontend visual gate at 1440x1000,
  1180x820, 820x1180, and 390x844; store screenshots/assertion summary under
  `.fleet/artifacts/a4h-readme-honesty/` for Codex inspection.
- Report exact commands/results in `.fleet/reports/a4h-readme-honesty.md`.
  No Reddit activity, PR merge, main push, deploy, external message, or subagent.
