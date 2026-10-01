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


def build_evidence(
    entry: dict[str, Any], network: str = "testnet-10"
) -> dict[str, Any]:
    deploy_tx = synthetic("deploy:" + entry["role"])
    raw = {
        "outpoint": {"transactionId": deploy_tx, "index": 0},
        "utxoEntry": {
            "amount": str(entry["genesis_value_sompi"]),
            "covenantId": entry["predicted_covenant_id"],
            "blockDaaScore": "123456789",
            "isCoinbase": False,
        },
    }
    return {
        "source_kind": "public_node_utxo",
        "network_id": network,
        "deploy_tx_id": deploy_tx,
        "deployed_instance_id": f"{deploy_tx}:0",
        "covenant_id": entry["predicted_covenant_id"],
        "amount_sompi": entry["genesis_value_sompi"],
        "block_hash": synthetic("block:" + entry["role"]),
        "block_daa_score": 123456789,
        "confirmations": 20,
        "raw_response": raw,
        "raw_response_sha256": d5.canonical_sha256(raw),
    }


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

    def test_complete_evidence_stays_blocked_on_recompute_and_accepts_bound_states(
        self,
    ) -> None:
        result = self.validate(self.confirmed(), self.twin)
        self.assertEqual(result["status"], d5.STATUS_EVIDENCE_PENDING_RECOMPUTE)
        self.assertFalse(result["executable"])
        guardian = result["covenant_ids"]["guardian_reputation"]
        self.assertEqual(
            d5.accept_state(
                result, {"network_id": "testnet-10", "covenant_id": guardian}
            ),
            "guardian_reputation",
        )
        lookalike = {
            "network_id": "testnet-10",
            "covenant_id": synthetic("lookalike-guardian"),
        }
        with self.assertRaisesRegex(d5.BindingError, "LOOKALIKE"):
            d5.accept_state(result, lookalike)
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

    def test_missing_evidence_blocks_and_accepts_nothing(self) -> None:
        doc = self.confirmed()
        del doc["evidence"]["guardian_reputation"]
        result = self.validate(doc, self.twin)
        self.assertEqual(result["status"], d5.STATUS_BLOCKED_EVIDENCE)
        self.assertIn("guardian_reputation", result["blockers"][-1])
        with self.assertRaisesRegex(d5.BindingError, "NOT_CONFIRMED"):
            d5.accept_state(
                result,
                {
                    "network_id": "testnet-10",
                    "covenant_id": synthetic("covenant:rule_storage"),
                },
            )

    def test_operator_claims_are_not_chain_evidence(self) -> None:
        for kind in ("operator_record", "operator_receipt", "fixture", "claimed"):
            doc = self.confirmed()
            doc["evidence"]["rule_storage"]["source_kind"] = kind
            with self.subTest(kind=kind):
                self.assert_code("EVIDENCE_SOURCE", doc, self.twin)

    def test_evidence_inconsistencies_rejected(self) -> None:
        def mutate(role: str, change: Any, code: str) -> None:
            doc = self.confirmed()
            change(doc["evidence"][role])
            self.assert_code(code, doc, self.twin)

        mutate(
            "rule_storage",
            lambda e: e.update(network_id="testnet-11"),
            "EVIDENCE_NETWORK",
        )
        mutate(
            "rule_storage",
            lambda e: e.update(raw_response_sha256=synthetic("tampered")),
            "EVIDENCE_RAW",
        )
        mutate(
            "rule_storage",
            lambda e: e.update(
                raw_response={"unexpected": True},
                raw_response_sha256=d5.canonical_sha256({"unexpected": True}),
            ),
            "EVIDENCE_RAW",
        )
        mutate(
            "rule_storage",
            lambda e: e.update(covenant_id=synthetic("claimed")),
            "EVIDENCE_INCONSISTENT",
        )
        mutate(
            "rule_storage",
            lambda e: e.update(deployed_instance_id=f"{e['deploy_tx_id']}:1"),
            "EVIDENCE_ANCHOR",
        )
        mutate(
            "rule_storage",
            lambda e: e.update(confirmations=d5.MIN_CONFIRMATIONS - 1),
            "EVIDENCE_ANCHOR",
        )
        mutate(
            "rule_storage", lambda e: e.update(block_hash="missing"), "EVIDENCE_ANCHOR"
        )

    def test_raw_response_with_other_covenant_or_anchor_rejected(self) -> None:
        def rewrite_raw(role: str, change: Any) -> dict[str, Any]:
            doc = self.confirmed()
            evidence = doc["evidence"][role]
            change(evidence["raw_response"])
            evidence["raw_response_sha256"] = d5.canonical_sha256(
                evidence["raw_response"]
            )
            raw = evidence["raw_response"]
            evidence["covenant_id"] = raw["utxoEntry"]["covenantId"]
            evidence["amount_sompi"] = int(raw["utxoEntry"]["amount"])
            return doc

        doc = rewrite_raw(
            "guardian_reputation",
            lambda r: r["utxoEntry"].update(covenantId=synthetic("lookalike")),
        )
        self.assert_code("COVENANT_MISMATCH", doc, self.twin)
        doc = rewrite_raw(
            "guardian_reputation", lambda r: r["outpoint"].update(index=1)
        )
        self.assert_code("EVIDENCE_ANCHOR", doc, self.twin)
        doc = rewrite_raw(
            "guardian_reputation", lambda r: r["utxoEntry"].update(isCoinbase=True)
        )
        self.assert_code("EVIDENCE_ANCHOR", doc, self.twin)
        doc = rewrite_raw(
            "guardian_reputation", lambda r: r["utxoEntry"].update(amount="1")
        )
        self.assert_code("EVIDENCE_INCONSISTENT", doc, self.twin)

    def test_evidence_for_unknown_role_rejected(self) -> None:
        doc = self.confirmed()
        doc["evidence"]["validator_staking_h001"] = doc["evidence"]["rule_storage"]
        self.assert_code("ROLE_UNKNOWN", doc, self.twin)


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
