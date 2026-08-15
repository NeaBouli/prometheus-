# Public Claim Audit - 2026-08-14

This audit classifies public claims against exact repository main
`5cd13bf6f9c170711e26364263bd0dcd8aad8c09`. Prometheus CI
`31747553871`, Security Audit `31747553891`, and Pages `31747553216`
passed on that commit. The machine-readable companion is
[`docs/evidence/public-claim-status-2026-08-14.json`](evidence/public-claim-status-2026-08-14.json).
Post-audit work is labeled explicitly and is not retroactively treated as
evidence on that pinned commit. GH-190 below is separate post-audit evidence:
protected PR #191 merged as exact main
`9c2fafffe680606a4ec6d1fc0b9915de9cb646e4`, with Prometheus CI
`31892079028`, Security Audit `31892079026`, and Pages `31892078930` passing.

## Claim Audit

| Claim | Current wording before correction | Evidence | Classification | Required correction | Files affected |
|---|---|---|---|---|---|
| Light Client malware detection | README described on-device Phi-3 as part of the present system; module comments described ONNX inference as running | On pinned audit commit `5cd13bf`, `modules/client/src/ai/phi3.rs` has no ONNX session, `blockchain/krc20.rs` returns a cache, and `network/zk_proof.rs` generates a SHA-256 placeholder. Separately labeled post-audit evidence: GH-190 adds bounded local Raw-CIDv1/exact-byte ingestion with 26 adversarial integration tests and merged through protected PR #191 as exact main `9c2faff` | Pinned baseline: implemented/tested development foundation. Post-audit exact main: additional implemented/tested local development foundation. Production detection remains blocked/unproven | Say explicitly that local caller-supplied ingestion is not canonical L1/IPFS loading, production YARA, operated P2P reporting, or production proving | README, Whitepaper, FAQ, roadmap, HTML, `llms.txt`, client status |
| Guardian model execution and economics | Guardian docs said nodes run LLaMA 3; public pages described generated rules, model quality, costs and break-even scenarios too much like current behavior | GH-144/PR #145 supplies hardened runtime configuration but explicitly performed no model pull or inference; GH-141/161 supply evidence machinery, not a completed independently evaluated run; no Guardian network, PROM market or active reward path exists | Implemented/tested machinery; real 8B/70B quality blocked/unproven; economics illustrative only | Distinguish runtime scaffolding from an evaluated model and label all cost, node-count, reward and break-even values as unproven scenarios | README, Whitepaper, FAQ, roadmap, Guardian economics HTML, Guardian README, `llms.txt` |
| YARA quality and authority | Public copy sometimes collapsed generated, valid, and usable rules | PR #171 verifies compile-only YARA-X structure; PR #174 creates a non-actionable draft; PR #178 evaluates only 20 synthetic buffers with authority `none` | Syntax validation and non-actionable draft implemented/tested; actionable production rules blocked | Keep syntax-valid, non-actionable, synthetic-quality, and actionable-authorized classes separate | README, Whitepaper, FAQ, roadmap, HTML, Guardian README |
| Validator network | Status tables called voting and slashing accepted without always stating that no network operates | Rust/Silverc Commit-Reveal, quorum, bond, and slashing tests pass; GH-147 binds a local membership file but proves no authority, key ownership, rotation, Sybil resistance, or multi-host operation | Implemented/tested state machines; operated validator network blocked/unproven | Preserve KAS-only staking and identify membership/operator trust assumptions | All core docs and status files |
| Rule persistence and censorship | Whitepaper and FAQ said nobody could delete, modify, or censor rules | `RuleStorageState.sil` tests canonical state/CID and `deactivateRule`; content is targeted for IPFS and no public replication/availability evidence exists | State/deactivation implemented/tested; IPFS operation and censorship resistance planned/unproven | Separate tamper evidence from content availability, replication, suppression resistance, and authorized deactivation | Whitepaper, FAQ, homepage, roadmap, `llms.txt` |
| Under-60-second lifecycle | Homepage metrics and status table displayed the value like achieved system performance | `modules/client/tests/e2e_threat_lifecycle.rs` is an in-process mock/stub fixture with no live node, real model, production proof, IPFS, or multi-host consensus | Implemented/tested development fixture; production performance target | Label under 60 seconds as a target until reproduced on a real public multi-host network | README, Whitepaper, roadmap, homepage, status, `llms.txt` |
| PROM purchase and issuance | Some pages said PROM can never be purchased while others planned a KAS/PROM pool | Tokenomics specify primary contribution issuance and a later secondary market; current Silverc fixtures do not implement KRC-20 minting and no emission or pool is deployed | Tokenomics planned; minting, emission, liquidity, and trading not implemented/deployed/active | Distinguish primary issuance from secondary trading; retain no-premine/ICO/presale/founder/foundation allocations | README, Whitepaper, FAQ, roadmap, homepage, `llms.txt` |
| PROM allocation | Public tables omitted the Community column or implied that no insider allocation meant no predefined allocation | Documented year-one split is Validators 40%, Guardians 30%, Reporters 20%, Dev Pool 5%, Community 5% | Planned tokenomics | Show both 5% pools and explain that they are predefined protocol pools, not founder/foundation allocations | README, Whitepaper, FAQ/HTML, homepage, `llms.txt` |
| Decentralization | Introductory copy claimed full decentralization and no central control | Current evidence uses owner-only policies, local trust anchors, configured membership, same-host transport evidence, and no public multi-host/Sybil/key-rotation/on-chain-attestation proof | Planned target; blocked/unproven operationally | Describe decentralization as a target property and state current operator/trust assumptions | README, Whitepaper, FAQ, roadmap, homepage, `llms.txt` |
| Testnet and rollout | H-001 success could be read as broad deployment evidence | Confirmed public H-001 evidence covers exactly one non-promotable Testnet-10 canary; the other six state deployments and production gates remain open | Demonstrated on Testnet only; production/Mainnet blocked | Keep canary, production deployment, and Mainnet readiness in separate classes | All status surfaces |
| Security audit handoff | The later-merged public handoff still called generic hygiene/dependency work unresolved | PR #184 fixed dependency-audit propagation; PR #185 added public-document hygiene; PR #186 closed their status. PR #183 still requires private, bounded follow-up before release | Generic hardening implemented/tested; private release gate blocked | Record completed generic work without treating it as resolution of private findings | Bridge and status documentation |

## Current Classification

1. **Implemented and tested:** development Light Client primitives and stub gates; local validator/contract state machines; compile-only YARA-X validation; deterministic non-actionable YARA draft; synthetic regression evaluator; bounded same-host Guardian transport/integration substrate; release and evidence tooling.
2. **Demonstrated on Testnet:** exactly the non-promotable `ValidatorStakingH001` Testnet-10 canary documented in `docs/evidence/gh-9-h001-canary-confirmed-2026-08-12.json`.
3. **Production-deployed:** no Prometheus protocol, model, validator network, rule distribution network, PROM emission, or Mainnet contract deployment is proven production-deployed. GitHub Pages publication is documentation hosting only.
4. **Planned or target architecture:** real Phi-3/ONNX detection, real and independently evaluated 8B/70B analysis, production proof artifacts, IPFS rule/model distribution, public multi-host operation, PROM issuance/liquidity, decentralized membership and attestation, mobile/desktop releases, and the under-60-second lifecycle.
5. **Blocked or not yet proven:** actionable rule authority, real-sample detection quality, production calibration, trusted membership/key rotation, Sybil resistance, public multi-host availability, IPFS replication/censorship resistance, six remaining state deployments, real metrics-oracle successor evidence, PROM minting/emission, Mainnet readiness, exact-release hardening, and the private-operator audit release gate.

## Remaining Gaps

- **Production blockers:** approved production proof relation/keys/ceremony and independent review; privacy-reviewed actionable analysis; real 8B/70B and Phi-3 evidence; six state deployments; metrics-oracle execution and successor evidence; public multi-host Guardian/validator/rule operation; exact rollout release hardening.
- **Unproven assumptions:** rule and model availability through replicated IPFS; trustworthy membership authority and key lifecycle; Sybil resistance; real-world detection/calibration; public-network lifecycle latency; sustained node availability.
- **Security and decentralization dependencies:** bounded private-operator audit assignment; authority/key/recipient attestation; on-chain ensemble attestation; independent cryptographic and privacy review; operated discovery, relay, replication, and recovery evidence.
- **Claims that remain disabled:** production malware detection, anonymous reporting, actionable or auto-published rules, active PROM rewards/trading, fully decentralized operation, censorship-proof availability, Mainnet readiness, and production under-60-second performance.

## Verification

The documentation patch was checked locally on 2026-08-14. These are actual
results, not planned CI steps:

| Command | Actual result |
|---|---|
| `python3 scripts/verify_public_claim_consistency.py` | PASS; 13 synchronized public/status surfaces |
| `python3 -m unittest scripts/test_public_claim_consistency.py` | PASS; 6 tests |
| `python3 scripts/check_public_documentation_hygiene.py` | PASS |
| `python3 -m unittest scripts/test_public_documentation_hygiene.py` | PASS; 11 tests |
| `python3 scripts/verify_h001_canary_closeout_evidence.py` | PASS; existing public canary evidence verified without reading signing material |
| `python3 -m unittest scripts/test_h001_canary_closeout_evidence.py` | PASS; 4 tests |
| `python3 scripts/check_memory_integrity.py` | PASS; all 8 canonical Memory files |
| `python3 -m unittest scripts/test_autodidactic.py` | PASS; 6 tests |
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS |
| `cargo test --workspace --all-targets` | PASS; no failures; 2 intentional live-network tests ignored in the client suite |
| `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. ../../.venv/bin/python -m pytest tests/ --tb=short` from `modules/guardian-node` | PASS; 1303 passed, 4 intentional live-model tests skipped |
| Black and Ruff on the new claim-check scripts | PASS after mechanical formatting |
| All workflow YAML parse, five public HTML pages parse, all JSON-LD blocks parse, required Pages files/meta checks | PASS |
| `git diff --check` | PASS |

Local Actionlint and Gitleaks executables were unavailable for the original
audit patch, so their protected GitHub checks remained mandatory before merge.
Those protected checks passed; the exact post-merge run IDs are recorded below
and in the append-only Bridge closeout.

Post-audit GH-190 closeout: protected PR #191 merged normally as
`9c2fafffe680606a4ec6d1fc0b9915de9cb646e4`; exact-main Prometheus CI
`31892079028`, Security Audit `31892079026`, and Pages `31892078930` passed.
Cache-busted live Pages and the commit-pinned README exposed the synchronized
GH-190 boundary markers. This evidence does not alter the pinned audit baseline
or any production-readiness classification above.

## Independent Review

The configured Kimi worker returned a provider usage-limit error before
analysis and changed no files. A secret-free Terra read-only fallback reviewed
the exact baseline and documentation work. It confirmed the principal status
classifications and identified residual homepage, Guardian, validator,
rule-distribution, performance and economics wording. Those findings are
resolved in this patch; Sol retained scope, integration, security review and
test ownership.
