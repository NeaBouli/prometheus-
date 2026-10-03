id: c2-k1-followup (C2a documentation reconciliation + C2b arithmetic adjudication)
status: ok (pending Codex review; no hosted dispatch until Codex coordinates)
worker: claude
branch: agent/claude/c2-k1-followup (base f090c35e26c7ee4b93667c7615488abb592e4599)
architecture_node: MS-B draft contracts -> documented attestation/runtime semantics
C2a (README reconciliation): modules/contracts/silverc/README.md sections DevIncentivePoolState, CommunityDonationsState and RuleStorageState now describe the current v2-draft transitions, versioned (-v2) attestation/tally digests with covenant instance binding, consensus-time windows (OpTxInputDaaScore + tx.time), participation/approval rules with terminal rejection, value backing, and the actual runtime test coverage; the frozen H-001 v1 reproduction sources are named explicitly as historical (earlier vote/execute transitions, not maintained). Unused quorum constants are documented as declared-but-unused (F2). No release claims.
C2b (arithmetic adjudication): conclusion recorded privately for Codex (~/Documents/Codex/prometheus-c2-f3-adjudication-20261004.md). Public summary: the pinned engine evaluates script arithmetic with checked 64-bit signed integers (overflow aborts the transaction, no wrap), amount introspection is range-checked, and silverc maps the operators 1:1 to those opcodes; value-backed quantities cannot reach the overflow region. Evidence is from locally available pinned sources; assumptions are listed in the private report.
F2 evidence: removing the two unused quorum constants leaves the compiled script byte-identical (checked against the reviewed expected-compiled hashes); it would only change the source hash in the release manifest. No source change made.
regressions: four donateKas arithmetic boundary runtime tests added to the pinned verifier (scripts/verify_silverc_h001.py RUST_TEST; no artifact change). NOT executed locally: the shared /tmp/prom-silverscript build directory has no git checkout (required by the harness), and cloning/downloading or a fresh large build is out of scope; they run in the h001-silverc-runtime job on the next coordinated hosted run.
tests:
  python3 -c "ast.parse(...)" on scripts/verify_silverc_h001.py -> OK; ruff check -> clean
  public gates (documentation hygiene, public-claim consistency, project-status consistency, memory integrity) -> PASS
  python3 -m unittest discover -s scripts -p 'test_*.py' -> 442 OK
  silverc temp-copy compile comparison (F2) -> identical script hashes, equal to the reviewed expectation
decisions_for_codex: (1) optional explicit donation upper bound (clarity only; changes compiled identity -> next reviewed bundle revision); (2) remove unused quorum constants in the next source revision (script-neutral, manifest-changing); (3) bound initial counters in the deployment-specific constructor review; (4) coordinate one hosted run to execute the new runtime regressions.
not changed: contracts, fixtures, provenance, pins, runtime/tooling/client, D5 acceptance (closed).
