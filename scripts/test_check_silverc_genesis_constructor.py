#!/usr/bin/env python3
"""Unit tests for the v2 genesis constructor checklist (no compiler needed)."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_silverc_genesis_constructor as gate  # noqa: E402  # pylint: disable=wrong-import-position

SAMPLE = gate.DEFAULT_CONTRACTS_DIR / "genesis-constructor.synthetic.sample.json"
OTHER_KEY = "51" * 32

Doc = dict[str, Any]
GENERIC_VALUES: dict[str, Any] = {
    "zero": 1,
    "false": True,
    "placeholder_key": OTHER_KEY,
    "role_key": "00" * 32,
    "free": -1,
}


def sample() -> Doc:
    """Return a fresh copy of the synthetic sample."""
    doc: Doc = json.loads(SAMPLE.read_text(encoding="utf-8"))
    return doc


def ctor(doc: Doc, contract: str) -> dict[str, Any]:
    """Return the constructor mapping of one contract."""
    values: dict[str, Any] = doc["contracts"][contract]["constructor"]
    return values


def fired(report: dict[str, Any]) -> set[str]:
    """Rule ids of all findings in a report."""
    return {f["rule_id"] for f in report["findings"]}


def set_value(contract: str, param: str, value: Any) -> Callable[[Doc], None]:
    """Mutation that sets one constructor value."""

    def mutate(doc: Doc) -> None:
        ctor(doc, contract)[param] = value

    return mutate


def generic_mutation(
    contract: str, param: str, kind: str
) -> Callable[[Doc], None] | None:
    """Default single-field violation for a rule kind (None when no violation exists)."""
    if kind == "zero_bytes":

        def mutate(doc: Doc) -> None:
            current = ctor(doc, contract)[param]
            ctor(doc, contract)[param] = "01" + current[2:]

        return mutate
    if kind in GENERIC_VALUES:
        return set_value(contract, param, GENERIC_VALUES[kind])
    return None


def set_entry(contract: str, field: str, value: Any) -> Callable[[Doc], None]:
    """Mutation that sets an extra (non-constructor) entry field."""

    def mutate(doc: Doc) -> None:
        doc["contracts"][contract][field] = value

    return mutate


def chain(*mutations: Callable[[Doc], None]) -> Callable[[Doc], None]:
    """Compose mutations."""

    def mutate(doc: Doc) -> None:
        for mutation in mutations:
            mutation(doc)

    return mutate


VS, GR, CD, DP, AT = (
    "ValidatorStakingState",
    "GuardianReputationState",
    "CommunityDonationsState",
    "DevIncentivePoolState",
    "GovernanceAutoTuningState",
)

# (description, mutation, expected rule ids exactly)
CUSTOM_CASES: list[tuple[str, Callable[[Doc], None], set[str]]] = [
    (
        "negative stake",
        chain(
            set_value(VS, "init_stake_kas", -1),
            set_value(VS, "init_active", False),
            set_entry(VS, "genesis_value_sompi", -100000000),
        ),
        {"G-VS-STAKE-KAS"},
    ),
    (
        "active below min stake",
        set_value(VS, "init_stake_kas", 9999),
        {"G-VS-ACTIVE", "G-VS-VALUE-BACKING"},
    ),
    (
        "active flag mismatch",
        set_value(VS, "init_active", False),
        {"G-VS-ACTIVE"},
    ),
    (
        "stake value backing",
        set_entry(VS, "genesis_value_sompi", 1),
        {"G-VS-VALUE-BACKING"},
    ),
    (
        "stake value backing i64 overflow",
        chain(
            set_value(VS, "init_stake_kas", 2**62),
            set_entry(VS, "genesis_value_sompi", 0),
        ),
        {"G-VS-VALUE-BACKING"},
    ),
    (
        "missing genesis value",
        lambda d: d["contracts"][VS].pop("genesis_value_sompi"),
        {"G-VS-VALUE-BACKING"},
    ),
    (
        "pre-set reputation",
        set_value(GR, "init_reputation", 99999),
        {"G-GR-REPUTATION"},
    ),
    ("unknown model type", set_value(GR, "init_model_type", 2), {"G-GR-MODEL-TYPE"}),
    (
        "negative donation pool",
        chain(
            set_value(CD, "init_pool_balance_kas", -1),
            set_entry(CD, "genesis_value_sompi", -100000000),
        ),
        {"G-CD-POOL-BALANCE-KAS"},
    ),
    (
        "pool value backing",
        set_entry(CD, "genesis_value_sompi", 0),
        {"G-CD-VALUE-BACKING"},
    ),
    (
        "unbacked PROM pool",
        set_value(DP, "init_pool_balance_prom", 5),
        {"G-DP-POOL-BALANCE-PROM"},
    ),
    (
        "negative PROM pool",
        set_value(DP, "init_pool_balance_prom", -5),
        {"G-DP-POOL-BALANCE-PROM"},
    ),
    ("pending complexity", set_value(DP, "init_complexity", 7), {"G-DP-COMPLEXITY"}),
    ("stake floor", set_value(AT, "init_min_stake_kas", 999), {"G-AT-MIN-STAKE-KAS"}),
    (
        "stake ceiling",
        set_value(AT, "init_min_stake_kas", 100001),
        {"G-AT-MIN-STAKE-KAS"},
    ),
    (
        "confidence floor",
        set_value(AT, "init_min_confidence_ki", 4999),
        {"G-AT-MIN-CONFIDENCE-KI"},
    ),
    (
        "confidence ceiling",
        set_value(AT, "init_min_confidence_ki", 9901),
        {"G-AT-MIN-CONFIDENCE-KI"},
    ),
    ("reward floor", set_value(AT, "init_reward_base", 9), {"G-AT-REWARD-BASE"}),
    ("reward ceiling", set_value(AT, "init_reward_base", 1001), {"G-AT-REWARD-BASE"}),
    ("fp rate high", set_value(AT, "init_fp_rate", 10001), {"G-AT-FP-RATE"}),
    ("fp rate negative", set_value(AT, "init_fp_rate", -1), {"G-AT-FP-RATE"}),
    (
        "fabricated tuning anchor",
        set_value(AT, "init_last_tuning_block", 5),
        {"G-AT-LAST-TUNING-BLOCK"},
    ),
    (
        "tuning anchor mismatch",
        chain(
            set_value(AT, "init_last_tuning_block", 5),
            set_entry(AT, "observed_tuning_anchor_daa", 6),
        ),
        {"G-AT-LAST-TUNING-BLOCK"},
    ),
    (
        "bad observed anchor",
        set_entry(AT, "observed_tuning_anchor_daa", 0),
        {"G-AT-LAST-TUNING-BLOCK"},
    ),
    (
        "validator key reused as governance key",
        set_value(VS, "init_validator_pk", "21" * 32),
        {"G-ROLE-KEY-REUSE"},
    ),
]


class GenesisChecklistTest(
    unittest.TestCase
):  # pylint: disable=too-many-public-methods
    """Sample, invariant, parser, coverage and verdict tests."""

    def run_gate(self, doc: Doc) -> dict[str, Any]:
        """Evaluate a document against the checkout contracts."""
        return gate.evaluate(doc)

    def assert_exact(self, doc: Doc, expected: set[str], label: str) -> None:
        """Assert the report is REJECT with exactly the expected rule ids."""
        report = self.run_gate(doc)
        self.assertEqual(fired(report), expected, label)
        self.assertEqual(report["verdict"], gate.VERDICT_REJECT, label)

    def test_sample_passes_without_acceptance(self) -> None:
        report = self.run_gate(sample())
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["verdict"], gate.VERDICT_NOT_ACCEPTED)
        self.assertIn("closed", report["acceptance"])

    def test_sample_is_labelled_synthetic(self) -> None:
        doc = sample()
        self.assertIs(doc["synthetic"], True)
        self.assertIn("SYNTHETIC", doc["description"])
        self.assertIn("Not a deployment set", doc["description"])

    def test_one_negative_case_per_generic_rule(self) -> None:
        for contract, params in gate.RULES.items():
            for param, kind in params.items():
                mutation = generic_mutation(contract, param, kind)
                if mutation is None:
                    continue
                with self.subTest(contract=contract, param=param):
                    doc = sample()
                    mutation(doc)
                    self.assert_exact(doc, {gate.rule_id(contract, param)}, param)

    def test_custom_rules(self) -> None:
        for label, mutation, expected in CUSTOM_CASES:
            with self.subTest(label):
                doc = sample()
                mutation(doc)
                self.assert_exact(doc, expected, label)

    def test_every_rule_id_has_a_negative_case(self) -> None:
        covered: set[str] = set()
        for contract, params in gate.RULES.items():
            for param, kind in params.items():
                if generic_mutation(contract, param, kind) is not None:
                    covered.add(gate.rule_id(contract, param))
        for _, _, expected in CUSTOM_CASES:
            covered |= expected
        covered.add("G-ROLE-SHARED-GOVERNANCE-KEY")  # see test_shared_governance_key
        participant = {
            gate.rule_id(c, p)
            for c, params in gate.RULES.items()
            for p, kind in params.items()
            if kind == "participant_key"
        }
        self.assertEqual(set(gate.all_rule_ids()) - participant - covered, set())

    def test_valid_tuning_anchor_and_model_type(self) -> None:
        doc = sample()
        set_value(AT, "init_last_tuning_block", 123456)(doc)
        set_entry(AT, "observed_tuning_anchor_daa", 123456)(doc)
        set_value(GR, "init_model_type", 1)(doc)
        set_value(GR, "init_reputation", 1000)(doc)
        set_value(VS, "init_stake_kas", 0)(doc)
        set_value(VS, "init_active", False)(doc)
        set_entry(VS, "genesis_value_sompi", 0)(doc)
        self.assertEqual(self.run_gate(doc)["findings"], [])

    def test_prom_pool_with_owner_decision_is_not_accepted(self) -> None:
        doc = sample()
        set_value(DP, "init_pool_balance_prom", 5)(doc)
        set_entry(DP, "pool_balance_owner_decision", "owner-decision-ref")(doc)
        report = self.run_gate(doc)
        self.assertEqual(fired(report), {"G-DP-POOL-BALANCE-PROM"})
        self.assertEqual(
            report["findings"][0]["severity"], gate.SEVERITY_OWNER_DECISION
        )
        self.assertEqual(report["verdict"], gate.VERDICT_NOT_ACCEPTED)

    def test_shared_governance_key(self) -> None:
        doc = sample()
        set_value("RuleStorageState", "init_governance_pk", "21" * 32)(doc)
        report = self.run_gate(doc)
        self.assertEqual(fired(report), {"G-ROLE-SHARED-GOVERNANCE-KEY"})
        self.assertEqual(report["verdict"], gate.VERDICT_NOT_ACCEPTED)

    # -- parser -----------------------------------------------------------

    def test_missing_parameter(self) -> None:
        doc = sample()
        del ctor(doc, VS)["init_bond_kas"]
        self.assert_exact(doc, {"G-PARSE-PARAMS"}, "missing")

    def test_extra_parameter(self) -> None:
        doc = sample()
        ctor(doc, VS)["init_extra"] = 0
        self.assert_exact(doc, {"G-PARSE-PARAMS"}, "extra")

    def test_reordered_parameters(self) -> None:
        doc = sample()
        values = ctor(doc, VS)
        items = list(values.items())
        items[1], items[2] = items[2], items[1]
        doc["contracts"][VS]["constructor"] = dict(items)
        report = self.run_gate(doc)
        self.assertEqual(fired(report), {"G-PARSE-PARAMS"})
        self.assertIn("order", report["findings"][0]["message"])

    def test_wrong_types(self) -> None:
        cases = [
            ("init_stake_kas", "10000"),
            ("init_stake_kas", True),
            ("init_stake_kas", 2**63),
            ("init_active", 1),
            ("init_validator_pk", "11" * 31),
            ("init_validator_pk", "AB" * 32),
            ("init_commitment", "00" * 31),
        ]
        for param, value in cases:
            with self.subTest(param=param, value=value):
                doc = sample()
                ctor(doc, VS)[param] = value
                self.assert_exact(doc, {"G-PARSE-TYPE"}, param)

    def test_h001_present_is_rejected(self) -> None:
        doc = sample()
        doc["contracts"]["ValidatorStakingH001"] = {
            "constructor": {"expected": "00" * 32}
        }
        self.assert_exact(doc, {"G-PARSE-H001-OUT-OF-SCOPE"}, "h001")

    def test_missing_and_unknown_contract(self) -> None:
        doc = sample()
        del doc["contracts"][CD]
        doc["contracts"]["Unknown"] = {"constructor": {}}
        self.assert_exact(doc, {"G-PARSE-CONTRACT-SET"}, "contract set")

    def test_schema_errors(self) -> None:
        mutations: list[Callable[[Doc], None]] = [
            lambda d: d.update(schema_version="other"),
            lambda d: d.update(placeholder_pubkey="xyz"),
            lambda d: d.update(extra=1),
            lambda d: d["contracts"][AT].update(unknown=1),
        ]
        for mutation in mutations:
            doc = sample()
            mutation(doc)
            self.assert_exact(doc, {"G-PARSE-SCHEMA"}, "schema")

    # -- coverage against the sources ----------------------------------------

    def test_every_constructor_parameter_is_covered(self) -> None:
        specs = gate.load_specs(gate.DEFAULT_CONTRACTS_DIR)
        for name, spec in specs.items():
            with self.subTest(contract=name):
                self.assertEqual([p.name for p in spec.params], list(gate.RULES[name]))

    def test_source_change_without_rule_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            for name in gate.RULES:
                text = (gate.DEFAULT_CONTRACTS_DIR / f"{name}.sil").read_text(
                    encoding="utf-8"
                )
                if name == VS:
                    text = text.replace(
                        "int init_withdraw_request_block",
                        "int init_withdraw_request_block,\n    int init_new_field",
                    )
                (tmp_dir / f"{name}.sil").write_text(text, encoding="utf-8")
            doc = sample()
            ctor(doc, VS)["init_new_field"] = 0
            report = gate.evaluate(doc, tmp_dir)
            self.assertIn("G-PARSE-UNCOVERED", fired(report))
            self.assertEqual(report["verdict"], gate.VERDICT_REJECT)

    def test_constants_come_from_source(self) -> None:
        specs = gate.load_specs(gate.DEFAULT_CONTRACTS_DIR)
        self.assertEqual(specs[VS].constants["MIN_STAKE_KAS"], 10000)
        self.assertEqual(specs[AT].constants["MIN_STAKE_KAS_FLOOR"], 1000)
        self.assertEqual(specs[CD].constants["SOMPI_PER_KAS"], 100000000)

    # -- verdict / CLI --------------------------------------------------------

    def test_no_accepting_verdict_exists(self) -> None:
        for verdict in gate.VERDICTS:
            for word in ("ACCEPTED", "DEPLOYABLE", "PASS", "APPROVED"):
                self.assertFalse(verdict.startswith(word), verdict)
        self.assertEqual(
            set(gate.VERDICTS), {"REJECT", "NOT_ACCEPTED_OWNER_DECISIONS_PENDING"}
        )

    def test_cli_exit_codes(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(gate.main(["--values", str(SAMPLE)]), 0)
        with tempfile.TemporaryDirectory() as tmp:
            bad = copy.deepcopy(sample())
            ctor(bad, "RuleStorageState")["init_status"] = 1
            bad_path = Path(tmp) / "bad.json"
            bad_path.write_text(json.dumps(bad), encoding="utf-8")
            broken = Path(tmp) / "broken.json"
            broken.write_text("{", encoding="utf-8")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(gate.main(["--values", str(bad_path)]), 1)
            self.assertIn("G-RS-STATUS", out.getvalue())
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gate.main(["--values", str(broken)]), 1)


if __name__ == "__main__":
    unittest.main()
