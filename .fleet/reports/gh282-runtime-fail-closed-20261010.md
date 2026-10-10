id: gh282-runtime-fail-closed-20261010
status: partial
worker: Codex (bounded existing guard/config/glue change)
branch: agent/codex/gh282-runtime-fail-closed-20261010
summary: Existing client runtime selection -> stub guard hop now defaults to
  the restrictive Beta policy, never implicit Development. Strict explicit
  profile checks and accepted production aliases are unchanged. Beta selection
  is not deployment authorization. No new module or runtime API.
files: runtime.rs, ci.yml, root/client READMEs, MAP and Fleet/Bridge records
tests:
  - rustfmt --edition 2021 --config-path /dev/null runtime.rs -> PASS;
    initial named-config attempt NOT RUN (file absent), corrected without adding config
  - parent-owned YAML equality -> PASS (only two test-step profiles and runtime step);
    production-code equality -> PASS (only Beta fallback), diff check -> PASS
  - new hosted runtime unit step -> pending; six child processes select unset,
    empty, invalid, Development, Beta and Mainnet without mutating shared env
  - complete existing Workspace/Clippy/loopback/performance/Guardian/public/Memory/
    pin/contract/Security gates -> pending automatic Draft PR
  - local target code/tests/builds -> NOT RUN (full isolation unavailable)
risks: Fallback deliberately applies the existing restrictive Beta policy rather
  than changing public APIs to Result or adding a new profile. Review required;
  no production, v2, inference, proof, deployment or issue-closure acceptance yet.
security: existing runtime-policy boundary changed; focused review required
next: exact hosted checks, scoped security/fix review before adoption;282 remains open.

The two existing development test steps explicitly select Development. The
runtime regression runs separately and child cases remove/override that value.
Existing real-binary negative/positive tests are retained, not weakened. Public
details are limited to the already public282 issue; no private operator data.
