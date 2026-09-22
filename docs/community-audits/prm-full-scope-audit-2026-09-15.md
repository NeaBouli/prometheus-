# Prometheus — Full-Scope Security Audit

- **Series:** Collateral Web3 Open Audits
- **Date:** 2026-09-15
- **Target:** NeaBouli/prometheus- @ `8b5da58a34172062cf644db52ba459385d151562` + live `neabouli.github.io/prometheus-/`
- **Scope:** Rust workspace (silverc-deployer, guardian-p2p, client, threat-hint, threat-proof, validator-node), Python guardian-node (77 files), operator scripts, CI/CD, container configs
- **Method:** 3 deep-recon agents + lead verification of every finding at exact file:line; read-only; no binaries executed against any network; no secrets read; `Prometheus-1.png` untouched (repo AGENTS.md)
- **Register:** PRM-01 … PRM-12 (this report) — **0 Critical / 1 High / 2 Medium / 8 Low / 1 Info**

---

## Executive summary

The Rust workspace is hardened to a degree this series has not seen before: **zero `unsafe` blocks**, only 13 non-test panic-capable sites workspace-wide (all proven input-unreachable), constant-time compares exactly where secrets are compared, fail-closed boundaries with redacted errors throughout, and a keyless deployer that re-verifies every signature and re-executes every script input locally before broadcast. The Python guardian-node matches that discipline (descriptor-identity file loading, BEGIN IMMEDIATE transactions, non-constructible receipts) — with **one real defect**: its SQLite operational-error helper silently falls through for non-lock errors, turning durable failures into false success receipts at the replay boundary (PRM-01). That function is the single highest-priority fix of this entire audit series.

Deployment context that calibrates severity: only the stateless H-001 canary verifier is on-chain (Testnet-10, holds no state or value); nothing in this report describes a live exploitable condition on a production system, because the project itself states none exists.

## Severity table

| ID | Severity | Title |
|----|----------|-------|
| PRM-01 | High | SQLite `_raise_operational_error` falls through for non-lock errors → false success receipts at the replay boundary |
| PRM-02 | Medium | Membership epoch monotonicity is uniqueness-based, not strictly increasing; bootstrap epochs re-usable as targets |
| PRM-03 | Medium | Runtime-mode gate defaults to stub-permissive "development" when env is unset/misspelled |
| PRM-04 | Low | `parse_simple_yara_rule` silently degrades declared YARA semantics (`all of them` → any-of) |
| PRM-05 | Low | Unbounded whole-file reads in scanner/detector file APIs (latent; no production caller) |
| PRM-06 | Low | Genesis CLI subcommands lack the input/output path-collision checks the oracle path has |
| PRM-07 | Low | v1 verifier binary not hash-pinned; ledger path preparation follows symlinks (weaker than v2/sibling patterns) |
| PRM-08 | Low | Policy/config files read via `read_text()` after lstat-only validation (TOCTOU inconsistency) |
| PRM-09 | Low | Dependency pinning gaps: `httpx>=` floor; `yara-x==1.4.0` far behind upstream; coincurve source-build note |
| PRM-10 | Low | docker-compose hardening nits: GID 0 container user, tmpfs without noexec, unauthenticated loopback vLLM |
| PRM-11 | Low | Dev rule cache (`krc20.rs`) unbounded, unvalidated, push-only |
| PRM-12 | Info | Hygiene cluster: `deny_unknown_fields` inconsistency, CI actions tag-pinned, self-attested hardening evidence, Cargo.lock duplicates, overflow-handling inconsistency, clock high-water fail-closed tradeoff |

---

## PRM-01 — High — SQLite `_raise_operational_error` falls through for non-lock errors

**Evidence (lead-verified):** `modules/guardian-node/jaeger/observable_approval_consumption.py:2456-2462` — the helper is annotated `NoReturn` but only raises for `SQLITE_BUSY`/`SQLITE_LOCKED`; for every other `OperationalError` (SQLITE_FULL, IOERR, CORRUPT, READONLY, CANTOPEN…) it **returns normally**. All six callers then continue into success paths:

- `_consume` (`:703-712`): after a failed INSERT, `except sqlite3.OperationalError as exc: _raise_operational_error(exc)` falls through to `return ObservableApprovalConsumptionReceipt(...)` — **a success receipt for an approval that was never durably consumed**. The replay boundary's core guarantee ("consume exactly once") silently breaks under transient I/O faults, and the approval remains replayable.
- `claim` (`:1507-1511`): returns an outbox claim whose lease was never persisted (double-processing across workers), or `NameError` when the failure hit before `row` was bound.
- `complete` (`:1672-1676`), `result` (`:1735-1739`): fabricated completion/result objects or `NameError`.
- `assert_authority_snapshot` (`:590`) and `__init__` (`:309`): silent pass despite failed reads/migrations.

Corroboration: the sibling module implements the same helper **with** a terminal raise — `guardian_membership_transition.py:1468-1485` (`raise GuardianMembershipTransitionError() from None`) — proving the intended pattern; the only test of the consumption helper (`tests/test_observable_approval_consumption.py:329-338`) parametrizes BUSY/LOCKED exclusively, so the fall-through is untested.

**Impact:** under disk-full/IO-error/corruption conditions the guardian emits success receipts for state transitions that never happened — replay protection, outbox leasing, and authority assertions all degrade silently exactly when the system is under fault stress. Conditional on an I/O fault occurring, but that is precisely the moment a durable ledger must not lie.

**Recommendation:** add the terminal `raise ObservableApprovalConsumptionError() from None` (two lines, mirroring the sibling); add a non-BUSY parametrized test. Small fix, highest priority of this series.

## PRM-02 — Medium — Membership epoch monotonicity is uniqueness-based, not strictly increasing

**Evidence:** `modules/guardian-node/jaeger/guardian_membership_transition.py:318-328,447-464` — `apply_transition` replay-checks `(transition_id, nonce, next_epoch)` and requires `previous_epoch == current`, but the **bootstrap epoch is never recorded as a transition output**, so an authority can sign a transition whose `next_epoch` equals the bootstrap epoch (rollback to a different source digest); `rotate_authority` likewise enforces uniqueness, not `next_authority_epoch > previous_authority_epoch`.

**Impact:** exploitation needs a valid authority signature (the trust anchor itself, i.e. compromised/coerced key), and every transition is durably logged — bounded blast radius. But "gapless/monotonic epochs" is a stated GH-246/GH-253 property that the code does not fully enforce.

**Recommendation (owner decision):** explicit `next_epoch > current_epoch` / `next_authority_epoch > authority_epoch` checks + recording bootstrap epochs at init.

## PRM-03 — Medium — Runtime-mode gate defaults to stub-permissive "development"

**Evidence (lead-verified):** `modules/client/src/runtime.rs:29-40` — `RuntimeMode::parse` maps anything not exactly `beta`/`mainnet`/`production`/`prod` (including **empty or misspelled** `PROMETHEUS_RUNTIME`) to `Development`; `require_stub_allowed` (`:49-65`) then permits every security-critical stub: ZK stub proofs (`network/zk_proof.rs:49-91`), dev rule ingestion (`blockchain/rule_ingest.rs:138`), dev IPFS fetch (`rule_fetch.rs:163`), KRC20 cache (`krc20.rs:77`), durable rule sync (`rule_checkpoint.rs:76`).

**Impact:** a production operator who forgets or mistypes the variable gets fail-**open** stub behavior — SHA-256 placeholder "proofs" and dev content paths accepted in a deployment believing it is beta/mainnet. Mitigating: the network-bound senders (GH-226/229/234) check explicit `testnet-10` network parameters rather than relying on this gate, and the project documents the stubs extensively.

**Recommendation:** invert the default (unknown/absent → forbid stubs; require explicit `development`), or fail startup when unset for release binaries.

## PRM-04 — Low — `parse_simple_yara_rule` silently degrades declared YARA semantics

**Evidence (lead-verified):** `modules/client/src/security/scanner.rs:210-243` — the condition section is parsed only as a section terminator; `required_matches` is hardcoded to 1 (`:60,242`), so a rule declaring `condition: all of them` is evaluated as **any-of-them**; only double-quoted ASCII literals are extracted (loose `strings:` detection, no escapes, no hex strings). The production ingestion grammar (`blockchain/rule_ingest.rs:337-391`) is strict and accepts only `any of them`, so the divergence is confined to this direct API — but any caller-authored "all of them" rule systematically produces false-positive classifications feeding confidence metrics.

**Recommendation:** reject non-`any of them` conditions (fail-closed like the ingest grammar) or mark the function test-only.

## PRM-05 — Low — Unbounded whole-file reads in scanner/detector file APIs

**Evidence:** `modules/client/src/security/scanner.rs:95` (`fs::read(path)`) and `modules/client/src/ai/detection.rs:66` (`tokio::fs::read(path)`) read whole files with no size cap, unlike the 16 MiB/64 KiB caps used everywhere else; verified no production call sites (`main.rs:270` only constructs the scanner for the validated rule-sync path). Latent: memory exhaustion + path-based read-vs-use TOCTOU if ever wired up.

**Recommendation:** apply the `take(MAX+1)` pattern used in `rule_sync_cli.rs:330-331` or document the caller obligation.

## PRM-06 — Low — Genesis CLI subcommands lack input/output collision checks

**Evidence:** `modules/silverc-deployer/src/main.rs` — `Prepare` (`:281-296`), `VerifySignature` (`:317-334`), `Broadcast` (`:335-399`), `Observe` (`:400-420`), `Preflight`/`Probe` (`:258-280`) pass output paths straight to the atomic `write_public_json`; the oracle subcommands all call `reject_oracle_output_collisions` (`:427-434,499-512,576-586`) and genesis `ImportSignature` uses `reject_import_output_collisions` (`lib.rs:1339-1351`). Operator error (`--result-out` = input path) silently overwrites an input file — local data destruction, not attacker-reachable.

**Recommendation:** apply the same collision rejection to the genesis commands.

## PRM-07 — Low — v1 verifier binary not hash-pinned; ledger path prep follows symlinks

**Evidence:** `modules/guardian-node/jaeger/threat_hint_ingress.py:755-780` — `_validate_verifier_binary` checks owner/mode/ancestors only, while the v2 preflight re-hashes the executable on every invocation (`threat_hint_v2_verified_preflight.py:386-430`); `_prepare_ledger_path` (`:722-752`) uses `candidate.stat()` (follows symlinks) for existing files where `signed_ballots.py:666-698` uses `lstat` + `O_NOFOLLOW` + exact-mode checks; `_kill_process_group` (`:783-791`) catches only `ProcessLookupError` (v2 also handles `PermissionError` with kill+wait retry). Same-user threat model throughout ⇒ Low.

## PRM-08 — Low — Policy files read via `read_text()` after lstat-only validation

**Evidence:** `threat_hint_v2_preflight.py:273-327` (read at `:280`), `threat_hint_service.py:66-72,193-218` — validate via `lstat`, then re-open with `Path.read_text()`: no `O_NOFOLLOW`, no fstat identity re-check, no post-read size check, deviating from the descriptor-identity pattern used in seven sibling loaders (`observable_approval_consumption.py:2273-2312`, `threat_hint_v2_promotion.py:425-465`, `guardian_membership_source.py:361-401`, …). Parent dirs are owner-only ⇒ Low.

## PRM-09 — Low — Dependency pinning gaps

**Evidence (lead-verified):** `modules/guardian-node/requirements.txt` — `httpx>=0.25.0` is the only unpinned runtime dependency (floor, not exact; supply-chain/reproducibility exposure for the vLLM HTTP path; mitigated by `trust_env=False` and loopback-only URLs in `llm_server.py:138,203,245`). `yara-x==1.4.0` is runtime-enforced (`yara_semantic_quality.py:584-592`) but far behind upstream (1.20.0 as of 2026-08); no known CVE found against 1.4.0 in a quick search, and usage is compile-only with includes disabled + bounded in-memory buffers (`yara_validation.py:202-218`) — small surface, but the pin should be a documented owner decision. `coincurve==21.0.0` has a known source-build packaging bug (missing LICENSE in cffi distribution; wheels unaffected).

## PRM-10 — Low — docker-compose hardening nits

**Evidence:** `modules/guardian-node/docker-compose.yml:36,96` — `user: "2000:0"` runs with **root group** (should be `2000:2000`); tmpfs mounts lack `noexec`; no CPU limit; the vLLM API is unauthenticated on loopback (any local process can query/prompt-inject the local analyzer — acceptable single-operator posture, worth a comment). Everything else verified accurate: tag+digest pin, `pull_policy: never`, literal `127.0.0.1` binds, `internal: true` network, `read_only`, `cap_drop: ALL`, `no-new-privileges`, bounded tmpfs/pids/mem/shm, offline HF/Transformers flags, models `:ro`, `init: true`, log rotation — enforced by `scripts/verify_guardian_vllm_compose.py`.

## PRM-11 — Low — Dev rule cache unbounded and unvalidated

**Evidence:** `modules/client/src/blockchain/krc20.rs:95-98` — `add_cached_rule` is push-only with no dedup, cap, or field validation; `fetch_latest_rules` (`:66-86`) returns it as "on-chain" rules behind the dev gate. Dev-surface only; the validated ingest path is unaffected.

## PRM-12 — Info — Hygiene cluster

- `deny_unknown_fields` applied inconsistently in silverc-deployer file formats (`SigningRequest` has it, `DeployRequest`/`GenesisFundingSpec`/`SignatureResponse`/`BroadcastJournal` do not; hashing keeps this fail-closed).
- CI actions pinned by mutable tag, not SHA (`actions/checkout@v7`, `gitleaks-action@v3`, …); positives: top-level `permissions: contents: read` in both workflows, no `pull_request_target`, no secrets beyond `GITHUB_TOKEN`, cargo-audit + pip-audit pinned.
- `ci.yml:1281-1319` constructs the "branch protection / required checks" evidence JSON **inline from static values + current commit**, then verifies it — the pipeline attests its own governance claims rather than querying GitHub state.
- Cargo.lock: 586 packages, 38 duplicated crate names (faster-hex 0.9/0.10, thiserror 1/2, getrandom ×3, …) inherited from pinned rusty-kaspa v2.0.1 / libp2p trees; weekly `cargo audit` gate exists.
- Bond math overflow-handling inconsistency: `commit.rs:73`/`reveal.rs:62` plain `u64` multiply vs `slashing/mod.rs:30` `saturating_mul` (economically unreachable, but invites copy-paste).
- Clock high-water fail-closed tradeoff (`signed_ballots.py:416-429`, `observable_approval_consumption.py:828-840`): any accepted far-future timestamp permanently rejects later real-time inputs — by design, but should be an explicit runbook entry.

---

## Verified strengths (evidence-checked by lead + agent)

- **Zero `unsafe` blocks** workspace-wide (grep-verified over `modules/**`).
- Panic surface: 13 non-test panic-capable sites, all input-unreachable (deployer `expect`s guarded by prior checks; threat-proof `expect`s behind validated constructors).
- **Deployer rigor:** exact 66-byte sighash modeling == final sigscript; SIG_HASH_ALL with covenant `authorizing_input=0`; covenant ID via consensus `covenant_id()`; deterministic interop vectors pinning txid/covenant/sighash/masses; storage mass re-derived after signing; fully checked fee arithmetic; broadcast reconciliation (contract UTXO → mempool) before submission; live funding UTXO re-validated immediately pre-submit; journal marked in-progress before `submit_transaction`; ambiguous state permanently forbids auto-resubmission; exclusive create via hard-link + fsync; acknowledgement must equal `signing_request_sha256`.
- **Oracle transition:** dual BIP340 verification; full local execution of every input via `TxScriptEngine` with covenant context before broadcast; covenant value preservation checked; live state/sponsor UTXO re-validation pre-broadcast.
- **Keyless posture:** secret-marker rejection on all JSON inputs; RPC URLs reject credentials/query/fragment; resolver testnet-10+wss only; CI greps the CLI for forbidden signing flags.
- **guardian-p2p:** strict multiaddr/relay-circuit validation; bounded frames + trailing-byte rejection both directions; shared inbound admission cap with Busy backpressure across all three protocols; v2 payloads canonically parsed at the codec layer against a separately trusted network id; transport identity file owner-only 0600, dirfd-relative NOFOLLOW, atomically published, buffers zeroized.
- **Local IPC:** peer-uid checks on connect and accept, owner-only socket+parent validation, bounded digest-bound acks with canonical JSON byte-identity.
- **Client:** loopback-only miner companion with credential rejection; quarantine vault with nlink/mode/length/SHA-256 verification + atomic hard-link publish; CID==content binding; durable anti-downgrade checkpoint (flock + dirfd + rename + dir fsync); domain-separated BIP340 signed snapshot envelope with ≤1h window; observation requires exact UTXO equality + DAA maturity.
- **Groth16 boundary:** canonical re-serialization of verifying key and proof; `gamma_abc_g1.len() == public_input_count+1` enforced at load; all invalid inputs → `Ok(false)`; injective public-input encoding.
- **Python guardian-node:** BIP340 via libsecp256k1 (coincurve), dual-signature rotation with proof-of-possession; canonical-JSON discipline with duplicate-key rejection; STRICT SQLite tables with shape/index/FK introspection validation and migration guards; non-constructible receipts (`__reduce__` raises); `hmac.compare_digest` at byte-identity compares; single-winner outbox lease via conditional UPDATE; model provenance walking with O_NOFOLLOW + inode-cycle detection; subprocess fully scrubbed env + hash-pinned binary + process-group cleanup.
- **Python operator scripts:** no `shell=True`/`eval`/`exec`/`pickle`/unsafe `yaml.load`/TLS-disabling anywhere; list-argv subprocess; tar member validation against traversal.
- CI: all three workflows green on baseline (`Prometheus CI`, `Security Audit`, `pages-build-deployment` 2026-09-13/14); `permissions: contents: read`; weekly cargo-audit + pip-audit.
