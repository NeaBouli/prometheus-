#!/usr/bin/env python3
"""Validation matrix for the D5 genesis-binding draft (no compiler, chain or wallet).

All outpoints, covenant ids and transaction ids below are synthetic labels
derived from fixed strings; they are not chain data and prove no deployment.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import re
import sys
import unittest
from hashlib import sha256
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import silverc_bundles as bundles  # noqa: E402
import silverc_genesis_binding_draft as d5  # noqa: E402

ROOT = bundles.ROOT
EXPECTED = ROOT / "modules/contracts/silverc/expected-compiled-artifacts.json"
SAMPLE = ROOT / "modules/contracts/silverc/genesis-binding.draft.sample.json"


def synthetic(label: str) -> str:
    return sha256(f"prometheus-d5-synthetic:{label}".encode()).hexdigest()


def compiled_entries() -> dict[str, dict[str, Any]]:
    data = json.loads(EXPECTED.read_text(encoding="utf-8"))
    return {entry["contract_name"]: entry for entry in data["fixtures"]}


def build_plan(bundle: bundles.Bundle) -> dict[str, Any]:
    compiled = compiled_entries()
    keys: dict[str, dict[str, str]] = {}
    contracts = []
    for role, spec in d5.ROLES.items():
        key_name = f"{spec.key_kind}:{role}"
        keys[key_name] = {
            "kind": spec.key_kind,
            "xonly_pubkey": d5.constructor_key_hex(
                bundle, spec.contract_name, spec.key_arg_index
            ),
        }
        contracts.append(
            {
                "role": role,
                "contract_name": spec.contract_name,
                "script_sha256": compiled[spec.contract_name]["script_sha256"],
                "constructor_args_sha256": compiled[spec.contract_name][
                    "constructor_args_sha256"
                ],
                "authority_key": key_name,
                "genesis_value_sompi": 100_000_000,
                "funding_outpoint": f"{synthetic('funding:' + role)}:0",
                "trusted_roles": [],
                "predicted_covenant_id": synthetic("covenant:" + role),
            }
        )
    return {
        "schema": d5.SCHEMA,
        "schema_version": d5.SCHEMA_VERSION,
        "network_id": "testnet-10",
        "release": {
            "bundle_id": bundle.bundle_id,
            "bundle_manifest_sha256": bundle.manifest_sha256,
            "silverscript_commit": "d25bd3427a093c17327ca3d6b9e1aa5f7688c863",
        },
        "authority_keys": keys,
        "contracts": contracts,
        "deployment_order": list(d5.ROLES),
    }


CANDIDATE_FIXTURE = (
    ROOT
    / "modules/silverc-deployer/tests/fixtures/d5-evidence-candidate.synthetic.json"
)
P2SH_SCRIPT = {"version": 0, "script_hex": "aa20" + "ab" * 32 + "87"}


def rehash(candidate: dict[str, Any]) -> dict[str, Any]:
    candidate["observed_snapshot_sha256"] = d5.canonical_sha256(candidate["observed"])
    unhashed = {k: v for k, v in candidate.items() if k != "candidate_sha256"}
    candidate["candidate_sha256"] = d5.canonical_sha256(unhashed)
    return candidate


def build_evidence(
    entry: dict[str, Any], network: str = "testnet-10"
) -> dict[str, Any]:
    """Synthetic candidate in the Rust D5 schema for one plan entry."""
    txid, index = entry["funding_outpoint"].split(":")
    deploy_tx = synthetic("deploy:" + entry["role"])
    candidate = {
        "schema_version": d5.CANDIDATE_SCHEMA_VERSION,
        "kind": d5.CANDIDATE_KIND,
        "status": d5.CANDIDATE_STATUS,
        "classification": list(d5.CANDIDATE_CLASSIFICATION),
        "trust_model": {
            "source": d5.CANDIDATE_TRUST_SOURCE,
            "independent_confirmation": False,
            "snapshot_note": d5.CANDIDATE_SNAPSHOT_NOTE,
            "missing_independent_checks": list(d5.CANDIDATE_MISSING_CHECKS),
        },
        "preparation": {
            "source": d5.CANDIDATE_PREPARATION_SOURCE,
            "network_id": network,
            "contract_name": entry["contract_name"],
            "request_sha256": synthetic("request:" + entry["role"]),
            "signing_request_sha256": synthetic("signing:" + entry["role"]),
            "funding_outpoint": {"transaction_id": txid, "index": int(index)},
            "genesis_output_value": entry["genesis_value_sompi"],
            "contract_output_index": 0,
            "contract_script_public_key": dict(P2SH_SCRIPT),
            "calculated_covenant_id": entry["predicted_covenant_id"],
            "expected_deploy_tx_id": deploy_tx,
        },
        "observed": {
            "source": d5.CANDIDATE_SNAPSHOT_SOURCE,
            "outpoint": {"transaction_id": deploy_tx, "index": 0},
            "amount": entry["genesis_value_sompi"],
            "script_public_key": dict(P2SH_SCRIPT),
            "covenant_id": entry["predicted_covenant_id"],
            "block_daa_score": 123_456_789,
            "is_coinbase": False,
        },
        "observed_snapshot_sha256": "",
        "observed_virtual_daa_score": 123_456_999,
        "daa_depth": 210,
        "relationships": list(d5.CANDIDATE_RELATIONSHIPS),
        "candidate_sha256": "",
    }
    return rehash(candidate)


def entry(plan: dict[str, Any], role: str) -> dict[str, Any]:
    return next(item for item in plan["contracts"] if item["role"] == role)


class D5Base(unittest.TestCase):
    def setUp(self) -> None:
        self.v2 = bundles.get_bundle(bundles.V2_DRAFT)
        # Test-only promotable twin of v2 to exercise the evidence path; never registered.
        self.twin = dataclasses.replace(
            self.v2, bundle_id="test-only-promotable-twin", promotable=True
        )
        self.compiled = compiled_entries()

    def validate(
        self, doc: dict[str, Any], bundle: bundles.Bundle, pin: str | None = None
    ) -> dict[str, Any]:
        return d5.validate_genesis_binding(
            doc,
            expected_plan_sha256=pin
            if pin is not None
            else d5.canonical_sha256(doc["plan"]),
            bundle=bundle,
            compiled=self.compiled,
        )

    def assert_code(
        self,
        code: str,
        doc: dict[str, Any],
        bundle: bundles.Bundle,
        pin: str | None = None,
    ) -> None:
        with self.assertRaises(d5.BindingError) as ctx:
            self.validate(doc, bundle, pin)
        self.assertEqual(ctx.exception.code, code, str(ctx.exception))


class PlanMatrixTest(D5Base):
    def test_v2_plan_is_consistent_but_never_executable(self) -> None:
        result = self.validate({"plan": build_plan(self.v2)}, self.v2)
        self.assertEqual(result["status"], d5.STATUS_PLAN_NOT_EXECUTABLE)
        self.assertFalse(result["executable"])
        self.assertIn(d5.RECOMPUTE_BLOCKER, result["blockers"])
        self.assertFalse(
            result["shared_governance_key"]
        )  # current fixtures use distinct placeholder keys

    def test_promotable_plan_still_blocked_on_recompute(self) -> None:
        result = self.validate({"plan": build_plan(self.twin)}, self.twin)
        self.assertEqual(result["status"], d5.STATUS_PLAN_PENDING_RECOMPUTE)
        self.assertFalse(result["executable"])

    def test_altered_plan_rejected_by_reviewed_pin(self) -> None:
        plan = build_plan(self.v2)
        pin = d5.canonical_sha256(plan)
        entry(plan, "guardian_reputation")["genesis_value_sompi"] += 1
        self.assert_code("PLAN_PIN", {"plan": plan}, self.v2, pin)

    def test_lookalike_compiled_contract_rejected(self) -> None:
        plan = build_plan(self.v2)
        entry(plan, "guardian_reputation")["constructor_args_sha256"] = synthetic(
            "forged-initial-reputation"
        )
        self.assert_code("COMPILED_IDENTITY", {"plan": plan}, self.v2)
        plan = build_plan(self.v2)
        entry(plan, "rule_storage")["script_sha256"] = synthetic("lookalike-script")
        self.assert_code("COMPILED_IDENTITY", {"plan": plan}, self.v2)

    def test_cross_bundle_substitution_rejected(self) -> None:
        plan = build_plan(self.v2)
        plan["release"]["bundle_id"] = bundles.H001_V1
        self.assert_code("BUNDLE", {"plan": plan}, self.v2)
        plan = build_plan(self.v2)
        plan["release"]["bundle_manifest_sha256"] = bundles.H001_V1_MANIFEST_SHA256
        self.assert_code("BUNDLE", {"plan": plan}, self.v2)

    def test_cross_network_rejected(self) -> None:
        for network in ("mainnet", "testnet-11", "sandbox", ""):
            plan = build_plan(self.v2)
            plan["network_id"] = network
            with self.subTest(network=network):
                self.assert_code("NETWORK", {"plan": plan}, self.v2)

    def test_role_substitutions_rejected(self) -> None:
        plan = build_plan(self.v2)
        entry(plan, "rule_storage")["contract_name"] = "CommunityDonationsState"
        self.assert_code("ROLE_CONTRACT", {"plan": plan}, self.v2)
        plan = build_plan(self.v2)
        a, b = entry(plan, "rule_storage"), entry(plan, "community_donations")
        a["role"], b["role"] = b["role"], a["role"]
        self.assert_code("ROLE_CONTRACT", {"plan": plan}, self.v2)
        plan = build_plan(self.v2)
        plan["contracts"].append(copy.deepcopy(entry(plan, "rule_storage")))
        self.assert_code("DUPLICATE_ROLE", {"plan": plan}, self.v2)
        plan = build_plan(self.v2)
        plan["contracts"] = [
            item for item in plan["contracts"] if item["role"] != "rule_storage"
        ]
        self.assert_code("ROLE_SET", {"plan": plan}, self.v2)
        plan = build_plan(self.v2)
        entry(plan, "rule_storage")["role"] = "validator_staking_h001"
        self.assert_code("ROLE_UNKNOWN", {"plan": plan}, self.v2)

    def test_authority_key_bindings(self) -> None:
        plan = build_plan(self.v2)
        plan["authority_keys"]["governance:rule_storage"]["kind"] = "metrics_oracle"
        self.assert_code("KEY_KIND", {"plan": plan}, self.v2)
        plan = build_plan(self.v2)
        plan["authority_keys"]["governance:rule_storage"]["xonly_pubkey"] = synthetic(
            "claimed-governance-key"
        )
        self.assert_code("KEY_CONSTRUCTOR", {"plan": plan}, self.v2)
        plan = build_plan(self.v2)
        entry(plan, "rule_storage")["authority_key"] = "governance:community_donations"
        self.assert_code("KEY_CONSTRUCTOR", {"plan": plan}, self.v2)
        plan = build_plan(self.v2)
        plan["authority_keys"]["governance:spare"] = {
            "kind": "governance",
            "xonly_pubkey": synthetic("spare"),
        }
        self.assert_code("KEY_UNUSED", {"plan": plan}, self.v2)

    def test_duplicate_and_malformed_anchors_rejected(self) -> None:
        plan = build_plan(self.v2)
        entry(plan, "rule_storage")["funding_outpoint"] = entry(
            plan, "dev_incentive_pool"
        )["funding_outpoint"]
        self.assert_code("DUPLICATE_OUTPOINT", {"plan": plan}, self.v2)
        plan = build_plan(self.v2)
        entry(plan, "rule_storage")["predicted_covenant_id"] = entry(
            plan, "dev_incentive_pool"
        )["predicted_covenant_id"]
        self.assert_code("DUPLICATE_COVENANT_ID", {"plan": plan}, self.v2)
        for bad in (
            "",
            "abc:0",
            f"{synthetic('x')}:-1",
            f"{synthetic('x')}:4294967296",
            synthetic("x").upper() + ":0",
        ):
            plan = build_plan(self.v2)
            entry(plan, "rule_storage")["funding_outpoint"] = bad
            with self.subTest(outpoint=bad):
                self.assert_code("OUTPOINT", {"plan": plan}, self.v2)
        for bad_value in (0, -1, True, "100"):
            plan = build_plan(self.v2)
            entry(plan, "rule_storage")["genesis_value_sompi"] = bad_value
            with self.subTest(value=bad_value):
                self.assert_code("GENESIS_VALUE", {"plan": plan}, self.v2)

    def test_circular_constructor_dependencies_rejected(self) -> None:
        plan = build_plan(self.v2)
        entry(plan, "rule_storage")["trusted_roles"] = ["guardian_reputation"]
        entry(plan, "guardian_reputation")["trusted_roles"] = ["rule_storage"]
        self.assert_code("CIRCULAR_DEPENDENCY", {"plan": plan}, self.v2)
        plan = build_plan(self.v2)
        entry(plan, "rule_storage")["trusted_roles"] = ["rule_storage"]
        self.assert_code("CIRCULAR_DEPENDENCY", {"plan": plan}, self.v2)
        plan = build_plan(self.v2)
        entry(plan, "rule_storage")["trusted_roles"] = ["dev_incentive_pool"]
        entry(plan, "dev_incentive_pool")["trusted_roles"] = ["community_donations"]
        entry(plan, "community_donations")["trusted_roles"] = ["rule_storage"]
        self.assert_code("CIRCULAR_DEPENDENCY", {"plan": plan}, self.v2)

    def test_acyclic_trust_requires_topological_deployment_order(self) -> None:
        plan = build_plan(self.v2)
        entry(plan, "rule_storage")["trusted_roles"] = ["guardian_reputation"]
        order = plan["deployment_order"]
        self.assertLess(order.index("guardian_reputation"), order.index("rule_storage"))
        self.assertEqual(
            self.validate({"plan": plan}, self.v2)["status"],
            d5.STATUS_PLAN_NOT_EXECUTABLE,
        )
        order.remove("guardian_reputation")
        order.append("guardian_reputation")
        self.assert_code("DEPLOYMENT_ORDER", {"plan": plan}, self.v2)
        plan = build_plan(self.v2)
        entry(plan, "rule_storage")["trusted_roles"] = ["unknown_role"]
        self.assert_code("TRUST_GRAPH", {"plan": plan}, self.v2)

    def test_shape_and_schema_rejections(self) -> None:
        plan = build_plan(self.v2)
        plan["schema_version"] = "1"
        self.assert_code("SCHEMA", {"plan": plan}, self.v2)
        plan = build_plan(self.v2)
        plan["self_declared_plan_sha256"] = synthetic("self-claim")
        self.assert_code("SHAPE", {"plan": plan}, self.v2)
        plan = build_plan(self.v2)
        entry(plan, "rule_storage")["covenant_id_confirmed"] = True
        self.assert_code("SHAPE", {"plan": plan}, self.v2)
        self.assert_code(
            "SHAPE", {"plan": build_plan(self.v2), "receipts": []}, self.v2
        )

    def test_role_table_matches_contract_sources(self) -> None:
        for role, spec in d5.ROLES.items():
            source = (
                ROOT / "modules/contracts/silverc" / f"{spec.contract_name}.sil"
            ).read_text(encoding="utf-8")
            header = re.search(r"contract\s+\w+\s*\((.*?)\)\s*\{", source, re.S)
            assert header is not None
            params = [
                part.split()[-1] for part in header.group(1).split(",") if part.strip()
            ]
            with self.subTest(role=role):
                self.assertEqual(params[spec.key_arg_index], spec.key_param)

    def test_deterministic_result(self) -> None:
        plan = build_plan(self.v2)
        reordered = json.loads(json.dumps(plan, sort_keys=False))
        reordered = dict(reversed(list(reordered.items())))
        self.assertEqual(
            self.validate({"plan": plan}, self.v2),
            self.validate({"plan": reordered}, self.v2),
        )


class EvidenceMatrixTest(D5Base):
    def confirmed(self) -> dict[str, Any]:
        plan = build_plan(self.twin)
        return {
            "plan": plan,
            "evidence": {
                item["role"]: build_evidence(item) for item in plan["contracts"]
            },
        }

    def test_v2_deployment_identity_refused(self) -> None:
        plan = build_plan(self.v2)
        doc = {
            "plan": plan,
            "evidence": {
                item["role"]: build_evidence(item) for item in plan["contracts"]
            },
        }
        self.assert_code("NON_PROMOTABLE", doc, self.v2)

    def test_complete_candidates_stay_blocked_and_accept_nothing(self) -> None:
        result = self.validate(self.confirmed(), self.twin)
        self.assertEqual(result["status"], d5.STATUS_EVIDENCE_PENDING_RECOMPUTE)
        self.assertFalse(result["executable"])
        self.assertFalse(result["independently_confirmed"])
        self.assertIn(d5.RECOMPUTE_BLOCKER, result["blockers"])
        self.assertIn(d5.TRUST_BLOCKER, result["blockers"])
        guardian = result["covenant_ids"]["guardian_reputation"]
        with self.assertRaisesRegex(d5.BindingError, "NOT_CONFIRMED"):
            d5.accept_state(
                result, {"network_id": "testnet-10", "covenant_id": guardian}
            )

    def test_acceptance_logic_for_a_hypothetical_confirmed_result(self) -> None:
        # Not producible by this draft: independently_confirmed is never set.
        result = dict(
            self.validate(self.confirmed(), self.twin), independently_confirmed=True
        )
        guardian = result["covenant_ids"]["guardian_reputation"]
        self.assertEqual(
            d5.accept_state(
                result, {"network_id": "testnet-10", "covenant_id": guardian}
            ),
            "guardian_reputation",
        )
        with self.assertRaisesRegex(d5.BindingError, "LOOKALIKE"):
            d5.accept_state(
                result,
                {"network_id": "testnet-10", "covenant_id": synthetic("lookalike")},
            )
        with self.assertRaisesRegex(d5.BindingError, "ROLE_SUBSTITUTION"):
            d5.accept_state(
                result,
                {
                    "network_id": "testnet-10",
                    "covenant_id": guardian,
                    "role": "rule_storage",
                },
            )
        with self.assertRaisesRegex(d5.BindingError, "EVIDENCE_NETWORK"):
            d5.accept_state(result, {"network_id": "mainnet", "covenant_id": guardian})

    def test_missing_evidence_blocks(self) -> None:
        doc = self.confirmed()
        del doc["evidence"]["guardian_reputation"]
        result = self.validate(doc, self.twin)
        self.assertEqual(result["status"], d5.STATUS_BLOCKED_EVIDENCE)
        self.assertIn("guardian_reputation", result["blockers"][-1])

    def test_context_substitutions_rejected_even_when_self_consistent(self) -> None:
        def mutate(role: str, change: Any, code: str) -> None:
            doc = self.confirmed()
            change(doc["evidence"][role])
            rehash(doc["evidence"][role])
            d5.verify_candidate_document(doc["evidence"][role])  # still self-consistent
            self.assert_code(code, doc, self.twin)

        def other_funding(c: dict[str, Any]) -> None:
            c["preparation"]["funding_outpoint"]["index"] += 1

        def other_value(c: dict[str, Any]) -> None:
            c["preparation"]["genesis_output_value"] += 1
            c["observed"]["amount"] += 1

        def other_id(c: dict[str, Any]) -> None:
            c["preparation"]["calculated_covenant_id"] = synthetic("lookalike")
            c["observed"]["covenant_id"] = synthetic("lookalike")

        mutate(
            "rule_storage",
            lambda c: c["preparation"].update(network_id="testnet-11"),
            "EVIDENCE_NETWORK",
        )
        mutate(
            "rule_storage",
            lambda c: c["preparation"].update(contract_name="CommunityDonationsState"),
            "ROLE_CONTRACT",
        )
        mutate("rule_storage", other_funding, "EVIDENCE_CONTEXT")
        mutate("rule_storage", other_value, "EVIDENCE_CONTEXT")
        mutate("rule_storage", other_id, "COVENANT_MISMATCH")

    def test_candidate_internal_inconsistencies_rejected(self) -> None:
        def mutate(change: Any, code: str, rehashed: bool = True) -> None:
            doc = self.confirmed()
            change(doc["evidence"]["guardian_reputation"])
            if rehashed:
                rehash(doc["evidence"]["guardian_reputation"])
            self.assert_code(code, doc, self.twin)

        mutate(
            lambda c: c["observed"].update(amount=c["observed"]["amount"] + 1),
            "EVIDENCE_INCONSISTENT",
        )
        mutate(
            lambda c: c["observed"].update(covenant_id=synthetic("x")),
            "COVENANT_MISMATCH",
        )
        mutate(lambda c: c["observed"]["outpoint"].update(index=1), "EVIDENCE_ANCHOR")
        mutate(lambda c: c["observed"].update(is_coinbase=True), "EVIDENCE_ANCHOR")
        mutate(
            lambda c: c["observed"].update(
                script_public_key={"version": 0, "script_hex": "51"}
            ),
            "EVIDENCE_INCONSISTENT",
        )
        mutate(
            lambda c: c.update(daa_depth=c["daa_depth"] + 1), "EVIDENCE_INCONSISTENT"
        )
        mutate(
            lambda c: (
                c["observed"].update(
                    block_daa_score=c["observed_virtual_daa_score"] + 1
                ),
                c.update(daa_depth=0),
            ),
            "EVIDENCE_ANCHOR",
        )
        mutate(
            lambda c: c["preparation"].update(contract_output_index=1),
            "EVIDENCE_ANCHOR",
        )
        mutate(
            lambda c: c["preparation"].update(
                expected_deploy_tx_id=c["preparation"]["funding_outpoint"][
                    "transaction_id"
                ]
            ),
            "EVIDENCE_ANCHOR",
        )
        mutate(
            lambda c: (
                c["observed"].update(
                    block_daa_score=c["observed"]["block_daa_score"] - 1
                ),
                c.update(daa_depth=c["daa_depth"] + 1),
            ),
            "EVIDENCE_HASH",
            rehashed=False,
        )
        mutate(
            lambda c: c.update(
                observed_virtual_daa_score=c["observed_virtual_daa_score"] + 1,
                daa_depth=c["daa_depth"] + 1,
            ),
            "EVIDENCE_HASH",
            rehashed=False,
        )

    def test_status_and_trust_upgrades_rejected(self) -> None:
        def mutate(change: Any, code: str) -> None:
            doc = self.confirmed()
            change(doc["evidence"]["rule_storage"])
            rehash(doc["evidence"]["rule_storage"])
            self.assert_code(code, doc, self.twin)

        mutate(lambda c: c.update(status="CONFIRMED"), "CANDIDATE_SCHEMA")
        mutate(lambda c: c["classification"].pop(), "CANDIDATE_SCHEMA")
        mutate(
            lambda c: c["trust_model"].update(independent_confirmation=True),
            "CANDIDATE_TRUST",
        )
        mutate(
            lambda c: c["trust_model"]["missing_independent_checks"].pop(),
            "CANDIDATE_TRUST",
        )
        mutate(
            lambda c: c["observed"].update(source="independent_explorer"),
            "CANDIDATE_SOURCE",
        )

    def test_unknown_missing_and_legacy_fields_rejected(self) -> None:
        for change in (
            lambda c: c["observed"].update(rpc_url="ws://127.0.0.1:17210"),
            lambda c: c.update(raw_response={}),
            lambda c: c["preparation"].pop("request_sha256"),
            lambda c: c.pop("observed_snapshot_sha256"),
        ):
            doc = self.confirmed()
            change(doc["evidence"]["rule_storage"])
            self.assert_code("SHAPE", doc, self.twin)

    def test_evidence_for_unknown_role_rejected(self) -> None:
        doc = self.confirmed()
        doc["evidence"]["validator_staking_h001"] = doc["evidence"]["rule_storage"]
        self.assert_code("ROLE_UNKNOWN", doc, self.twin)


class CrossLanguageFixtureTest(unittest.TestCase):
    """The Rust deployer produced this candidate; Python must verify the same bytes."""

    def test_rust_candidate_verifies_and_constants_match(self) -> None:
        candidate = json.loads(CANDIDATE_FIXTURE.read_text(encoding="utf-8"))
        d5.verify_candidate_document(candidate)
        self.assertEqual(candidate["kind"], d5.CANDIDATE_KIND)
        self.assertEqual(candidate["status"], d5.CANDIDATE_STATUS)
        self.assertEqual(candidate["classification"], d5.CANDIDATE_CLASSIFICATION)
        self.assertEqual(candidate["relationships"], d5.CANDIDATE_RELATIONSHIPS)
        self.assertEqual(
            candidate["trust_model"]["snapshot_note"], d5.CANDIDATE_SNAPSHOT_NOTE
        )
        self.assertEqual(
            candidate["trust_model"]["missing_independent_checks"],
            d5.CANDIDATE_MISSING_CHECKS,
        )

    def test_tampered_rust_candidate_rejected(self) -> None:
        candidate = json.loads(CANDIDATE_FIXTURE.read_text(encoding="utf-8"))
        candidate["observed"]["block_daa_score"] -= 1
        with self.assertRaises(d5.BindingError):
            d5.verify_candidate_document(candidate)


class SampleFixtureTest(D5Base):
    def test_committed_sample_matches_builder_and_is_not_executable(self) -> None:
        sample = json.loads(SAMPLE.read_text(encoding="utf-8"))
        self.assertEqual(sample, {"plan": build_plan(self.v2)})
        result = self.validate(sample, self.v2)
        self.assertEqual(result["status"], d5.STATUS_PLAN_NOT_EXECUTABLE)

    def test_module_is_not_executable(self) -> None:
        source = Path(d5.__file__).read_text(encoding="utf-8")
        self.assertNotIn("__main__", source)
        self.assertNotIn("argparse", source)
        self.assertNotIn("write_text", source)


if __name__ == "__main__":
    unittest.main()
